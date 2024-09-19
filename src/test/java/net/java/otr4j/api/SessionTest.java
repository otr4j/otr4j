/*
 * otr4j, the open source java otr library.
 *
 * Distributable under LGPL license.
 * See terms of license at gnu.org.
 *
 * SPDX-License-Identifier: LGPL-3.0-only
 */

package net.java.otr4j.api;

import net.java.otr4j.crypto.DHKeyPair;
import net.java.otr4j.crypto.DSAKeyPair;
import net.java.otr4j.crypto.OtrCryptoEngine4;
import net.java.otr4j.crypto.ed448.ECDHKeyPair;
import net.java.otr4j.crypto.ed448.EdDSAKeyPair;
import net.java.otr4j.crypto.ed448.Point;
import net.java.otr4j.io.EncodedMessage;
import net.java.otr4j.io.MessageProcessor;
import net.java.otr4j.messages.ClientProfilePayload;
import net.java.otr4j.messages.DataMessage4;
import net.java.otr4j.messages.EncodedMessageParser;
import net.java.otr4j.messages.IdentityMessage;
import net.java.otr4j.util.BlockingSubmitter;
import net.java.otr4j.util.ByteArrays;
import net.java.otr4j.util.ConditionalBlockingQueue;
import net.java.otr4j.util.ConditionalBlockingQueue.Predicate;
import org.junit.Before;
import org.junit.Test;

import javax.annotation.Nonnull;
import java.math.BigInteger;
import java.net.ProtocolException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Random;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.logging.Logger;

import static java.lang.Integer.MAX_VALUE;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Arrays.asList;
import static java.util.Objects.requireNonNull;
import static java.util.logging.Level.FINEST;
import static net.java.otr4j.api.OtrPolicy.ALLOW_V2;
import static net.java.otr4j.api.OtrPolicy.ALLOW_V3;
import static net.java.otr4j.api.OtrPolicy.ALLOW_V4;
import static net.java.otr4j.api.OtrPolicy.ERROR_START_AKE;
import static net.java.otr4j.api.OtrPolicy.OPPORTUNISTIC;
import static net.java.otr4j.api.OtrPolicy.OTRL_POLICY_MANUAL;
import static net.java.otr4j.api.OtrPolicy.OTRV4_INTERACTIVE_ONLY;
import static net.java.otr4j.api.OtrPolicy.WHITESPACE_START_AKE;
import static net.java.otr4j.api.SessionStatus.ENCRYPTED;
import static net.java.otr4j.api.SessionStatus.FINISHED;
import static net.java.otr4j.api.SessionStatus.PLAINTEXT;
import static net.java.otr4j.crypto.DSAKeyPair.generateDSAKeyPair;
import static net.java.otr4j.io.MessageProcessor.otrEncoded;
import static net.java.otr4j.io.MessageProcessor.otrFragmented;
import static net.java.otr4j.io.MessageProcessor.writeMessage;
import static net.java.otr4j.session.OtrSessionManager.createSession;
import static net.java.otr4j.util.Arrays.contains;
import static net.java.otr4j.util.BlockingQueuesTestUtils.drop;
import static net.java.otr4j.util.BlockingQueuesTestUtils.rearrangeFragments;
import static net.java.otr4j.util.BlockingQueuesTestUtils.shuffle;
import static net.java.otr4j.util.SecureRandoms.randomBytes;
import static org.bouncycastle.util.encoders.Base64.toBase64String;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

// TODO handle case where we store skipped message keys such that we can decrypt message that is received out-of-order, i.e. later than it was supposed to arrive.
// TODO add test to prove that we can start new (D)AKE in encrypted/finished Message state.
// TODO implement a test that produces arbitrary, specially crafted message in between real ones to throw off the Double Ratchet: only authentic messages must ever contribute to the ratcheting process in any way.
@SuppressWarnings({"resource", "DataFlowIssue"})
public class SessionTest {

    private static final Logger LOGGER = Logger.getLogger(SessionTest.class.getName());

    private static final SecureRandom RANDOM = new SecureRandom();

    private static final String OTRv23QueryMessage = "<p>?OTRv23?\n"
            + "<span style=\"font-weight: bold;\">Bob@Wonderland/</span> has requested an <a href=\"http://otr.cypherpunks.ca/\">Off-the-Record private conversation</a>. However, you do not have a plugin to support that.\n"
            + "See <a href=\"http://otr.cypherpunks.ca/\">http://otr.cypherpunks.ca/</a> for more information.</p>";

    private static final String[] UNICODE_LINES = {
            "plainAscii",
            "བོད་རིགས་ཀྱི་བོད་སྐད་བརྗོད་པ་དང་ བོད་རིགས་མང་ཆེ་བ་ནི་ནང་ཆོས་བྱེད་པ་དང་",
            "تبتی قوم (Tibetan people)",
            "Учените твърдят, че тибетците нямат",
            "Câung-cŭk (藏族, Câung-ngṳ̄: བོད་པ་)",
            "チベット系民族（チベットけいみんぞく）",
            "原始汉人与原始藏缅人约在公元前4000年左右分开。",
            "Տիբեթացիներ (ինքնանվանումը՝ պյոբա),",
            "... Gezginci olarak",
            "شْتَن Xotan",
            "Tibeťané jsou",
            "ئاچاڭ- تىبەت مىللىتى",
            "Miscellaneous Symbols and Pictographs[1][2] Official Unicode Consortium code chart (PDF)",
            "Royal Thai (ราชาศัพท์)",
            "טיילאנדיש123 (ภาษาไทย)",
            "ជើងអក្សរ cheung âksâr",
            "중화인민공화국에서는 기본적으로 한족은 ",
            "पाठ्यांशः अत्र उपलभ्यतेसर्जनसामान्यलक्षणम्/Share-",
            "திபெத்துக்கு வெகள்",
            "អក្សរសាស្រ្តខែ្មរមានប្រវ៌ត្តជាងពីរពាន់ឆ្នាំមកហើយ ",
            "tabbackslashT\t",
            "backslashR\r",
            "NEWLINE\n",
            "བོད་རིགས་ཀྱི་བོད་སྐད་བརྗོད་པ་དང་ བོད་རིགས་མང་ཆེ་བ་ནི་ནང་ཆོས་བྱེད་པ་དང་ འགའ་ཤས་བོན་ཆོས་བྱེད་ཀྱིན་ཡོད་ འགའ་ཤས་ཁ་ཆེའི་ཆོས་བྱེད་ཀྱིན་ཡོད། ནང་ཆོས་ཀྱིས་བོད་ཀྱི་སྒྱུ་རྩལ་དང་ཟློས་གར་ཁང་རྩིག་བཟོ་རིག་ལ་སོགས་ལ་ཤུགས་རྐྱེན་ཆེན་པོ་འཐེབ་ཀྱིན་ཡོད།",
            "تبتی قوم (Tibetan people) (تبتی: བོད་པ་، وائلی: Bodpa، چینی: 藏族؛ پنین: Zàng",
            "تبتی قوم سے ربط رکھنے والے صفحات",
            "Учените твърдят, че тибетците нямат проблеми с разредения въздух и екстремни студове, защото не са хора. Размус Нилсен от университета Бъркли и неговите сътрудници от лабораторията за ДНК изследвания в Китай твърдят, че тибетците",
            "Câung-cŭk (藏族, Câung-ngṳ̄: བོད་པ་) sê Câung-kṳ̆ (bău-guók gĭng-dáng gì Să̤-câung) gì siŏh ciáh mìng-cŭk, iâ sê Dṳ̆ng-guók guăng-huŏng giĕ-dêng gì „Dṳ̆ng-huà Mìng-cŭk“ cĭ ék.",
            "チベット系民族（チベットけいみんぞく）は、主としてユーラシア大陸中央部のチベット高原上に分布する民族で、モンゴロイドに属する。",
            "原始汉人与原始藏缅人约在公元前4000年左右分开。原始汉人逐渐移居到黄河流域从事农业，而原始藏缅人则向西南迁徙并从事游牧业。而之后藏族与缅族又进一步的分离。[1]原始藏缅人屬於古羌人系統，发羌入藏為吐蕃王朝發跡的一種歷史學觀點",
            "Տիբեթացիներ (ինքնանվանումը՝ պյոբա), ժողովուրդ, Տիբեթի արմատական բնակչությունը։ Բնակվում են Չինաստանում (Տիբեթի ինքնավար շրջան, Դանսու, Ցինհայ, Սըչուան, Ցուննան նահանգներ), որոշ մասը՝ Հնդկաստանում, Նեպալում և Բութանում։ Ընդհանուր թիվը՝ մոտ 5 մլն (1978)։ Խոսում ենտիբեթերենի բարբառներով։ Հիմնական կրոնը լամայականությունն է (բուդդայականության հյուսիսային ճյուղ)։ Տիբեթացիների կեսից ավելին լեռնային նստակյաց երկրագործներ են (աճեցնում են հիմնականում գարի, ցորեն, բրինձ), մնացածներրը՝ կիսանստակյաց հողագործ-անասնապահներ և թափառակեցիկ անասնապահներ (բուծում են եղնայծ, ձի, ոչխար, այծ)։ Զարգացած են արհեստները։ XX դ․ սկզբին ստեղծվել են արդիական մի քանի փոքր ձեռնարկություններ",
            "... Gezginci olarak yabancılarla karışanlar \"شْتَن Xotan\" ve \"تبت Tübüt\" halkı ile \"طَنغُت Tenğüt\"lerin bir kısmıdır.\"[1] ve \"Tübütlüler تبت adında birinin oğullarıdır. Bu, Yemenli bir kimsedir, orada birini öldürmüş, korkusundan kaçmış, bir gemiye binerek Çine gelmiş, \"Tibet\" ülkesi onun hoşuna gitmiş, orada yerleşmiş; çoluğu çocuğu çoğalmış, torunları Türk topraklarından bin beşyüz fersah yer almışlar, Çin ülkesi Tibetin doğu tarafındadır.\"[2] şeklinde yorumlar.",
            "Tibeťané jsou domorodí obyvatelé Tibetu a přilehlých oblastí Centrální Asie, počínaje Myanmarem na jihovýchodě a Čínskou lidovou republikou na východě konče. Počet Tibeťanů je těžko odhadnutelný, podle údajů Ústřední tibetské správy populace Tibeťanů klesla od roku 1959 z 6,3 milionů na 5,4 milionů",
            "ئاچاڭ مىللىتى - بەيزۇ مىللىتى - بونان مىللىتى - بۇلاڭ مىللىتى - بۇيى مىللىت - چوسون مىللىتى - داغۇر مىللىتى - دەيزۇ مىللىتى - دېئاڭ مىللىتى - دۇڭشياڭ مىللىتى - دۇڭزۇ مىللىتى - دۇلۇڭ مىللىتى - رۇس مىللىتى - ئورۇنچون مىللىتى - ئېۋېنكى مىللىتى - گېلاۋ مىللىتى - ھانى مىللىتى - قازاق مىللىتى - خېجى مىللىتى - خۇيزۇ مىللىتى - گاۋشەن مىللىتى - خەنزۇ مىللىتى - كىنو مىللىتى - جىڭزۇ مىللىتى - جخڭپو مىللىتى - قىرغىز مىللىتى - لاخۇ مىللىتى - لىزۇ مىللىتى - لىسۇ مىللىتى - لوبا مىللىتى - مانجۇ مىللىتى - ماۋنەن مىللىتى - مېنبا مىللىتى - موڭغۇل مىللىتى - مياۋزۇ مىللىتى - مۇلاۋ مىللىتى - ناشى مىللىتى - نۇزۇ مىللىتى - پۇمى مىللىتى - چياڭزۇ مىللىتى - سالار مىللىتى - شېزۇ مىللىتى - شۈيزۇلار - تاجىك مىللىتى - تاتار مىللىتى - تۇجيا مىللىتى - تۇزۇ مىللىتى - ۋازۇ مىللىتى - ئۇيغۇر مىللىتى - ئۆزبېك مىللىتى - شىبە مىللىتى - ياۋزۇ مىللىتى - يىزۇ مىللىتى - يۇغۇر مىللىتى - تىبەت مىللىتى - جۇاڭزۇ مىللىتى",
            "Miscellaneous Symbols and Pictographs[1][2]Official Unicode Consortium code chart (PDF)    0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   FU+1F30x 🌀  🌁  🌂  🌃  🌄  🌅  🌆  🌇  🌈  🌉  🌊  🌋  🌌  🌍  🌎  🌏U+1F31x 🌐  🌑  🌒  🌓  🌔  🌕  🌖  🌗  🌘  🌙  🌚  🌛  🌜  🌝  🌞  🌟U+1F32x 🌠  🌡  🌢  🌣  🌤  🌥  🌦  🌧  🌨  🌩  🌪  🌫  🌬         U+1F33x 🌰  🌱  🌲  🌳  🌴  🌵  🌶  🌷  🌸  🌹  🌺  🌻  🌼  🌽  🌾  🌿U+1F34x 🍀  🍁  🍂  🍃  🍄  🍅  🍆  🍇  🍈  🍉  🍊  🍋  🍌  🍍  🍎  🍏U+1F35x 🍐  🍑  🍒  🍓  🍔  🍕  🍖  🍗  🍘  🍙  🍚  🍛  🍜  🍝  🍞  🍟U+1F36x 🍠  🍡  🍢  🍣  🍤  🍥  🍦  🍧  🍨  🍩  🍪  🍫  🍬  🍭  🍮  🍯U+1F37x 🍰  🍱  🍲  🍳  🍴  🍵  🍶  🍷  🍸  🍹  🍺  🍻  🍼  🍽     U+1F38x 🎀  🎁  🎂  🎃  🎄  🎅  🎆  🎇  🎈  🎉  🎊  🎋  🎌  🎍  🎎  🎏U+1F39x 🎐  🎑  🎒  🎓  🎔  🎕  🎖  🎗  🎘  🎙  🎚  🎛  🎜  🎝  🎞  🎟U+1F3Ax 🎠  🎡  🎢  🎣  🎤  🎥  🎦  🎧  🎨  🎩  🎪  🎫  🎬  🎭  🎮  🎯U+1F3Bx 🎰  🎱  🎲  🎳  🎴  🎵  🎶  🎷  🎸  🎹  🎺  🎻  🎼  🎽  🎾  🎿U+1F3Cx 🏀  🏁  🏂  🏃  🏄  🏅  🏆  🏇  🏈  🏉  🏊  🏋  🏌  🏍  🏎 U+1F3Dx                 🏔  🏕  🏖  🏗  🏘  🏙  🏚  🏛  🏜  🏝  🏞  🏟U+1F3Ex 🏠  🏡  🏢  🏣  🏤  🏥  🏦  🏧  🏨  🏩  🏪  🏫  🏬  🏭  🏮  🏯U+1F3Fx 🏰  🏱  🏲  🏳  🏴  🏵  🏶  🏷                             U+1F40x 🐀  🐁  🐂  🐃  🐄  🐅  🐆  🐇  🐈  🐉  🐊  🐋  🐌  🐍  🐎  🐏U+1F41x 🐐  🐑  🐒  🐓  🐔  🐕  🐖  🐗  🐘  🐙  🐚  🐛  🐜  🐝  🐞  🐟U+1F42x 🐠  🐡  🐢  🐣  🐤  🐥  🐦  🐧  🐨  🐩  🐪  🐫  🐬  🐭  🐮  🐯U+1F43x 🐰  🐱  🐲  🐳  🐴  🐵  🐶  🐷  🐸  🐹  🐺  🐻  🐼  🐽  🐾  🐿U+1F44x 👀  👁  👂  👃  👄  👅  👆  👇  👈  👉  👊  👋  👌  👍  👎  👏U+1F45x 👐  👑  👒  👓  👔  👕  👖  👗  👘  👙  👚  👛  👜  👝  👞  👟U+1F46x 👠  👡  👢  👣  👤  👥  👦  👧  👨  👩  👪  👫  👬  👭  👮  👯U+1F47x 👰  👱  👲  👳  👴  👵  👶  👷  👸  👹  👺  👻  👼  👽  👾  👿U+1F48x 💀  💁  💂  💃  💄  💅  💆  💇  💈  💉  💊  💋  💌  💍  💎  💏U+1F49x 💐  💑  💒  💓  💔  💕  💖  💗  💘  💙  💚  💛  💜  💝  💞  💟U+1F4Ax 💠  💡  💢  💣  💤  💥  💦  💧  💨  💩  💪  💫  💬  💭  💮  💯U+1F4Bx 💰  💱  💲  💳  💴  💵  💶  💷  💸  💹  💺  💻  💼  💽  💾  💿U+1F4Cx 📀  📁  📂  📃  📄  📅  📆  📇  📈  📉  📊  📋  📌  📍  📎  📏U+1F4Dx 📐  📑  📒  📓  📔  📕  📖  📗  📘  📙  📚  📛  📜  📝  📞  📟U+1F4Ex 📠  📡  📢  📣  📤  📥  📦  📧  📨  📩  📪  📫  📬  📭  📮  📯U+1F4Fx 📰  📱  📲  📳  📴  📵  📶  📷  📸  📹  📺  📻  📼  📽  📾 U+1F50x 🔀  🔁  🔂  🔃  🔄  🔅  🔆  🔇  🔈  🔉  🔊  🔋  🔌  🔍  🔎  🔏U+1F51x 🔐  🔑  🔒  🔓  🔔  🔕  🔖  🔗  🔘  🔙  🔚  🔛  🔜  🔝  🔞  🔟U+1F52x 🔠  🔡  🔢  🔣  🔤  🔥  🔦  🔧  🔨  🔩  🔪  🔫  🔬  🔭  🔮  🔯U+1F53x 🔰  🔱  🔲  🔳  🔴  🔵  🔶  🔷  🔸  🔹  🔺  🔻  🔼  🔽  🔾  🔿U+1F54x 🕀  🕁  🕂  🕃  🕄  🕅  🕆  🕇  🕈  🕉  🕊                 U+1F55x 🕐  🕑  🕒  🕓  🕔  🕕  🕖  🕗  🕘  🕙  🕚  🕛  🕜  🕝  🕞  🕟U+1F56x 🕠  🕡  🕢  🕣  🕤  🕥  🕦  🕧  🕨  🕩  🕪  🕫  🕬  🕭  🕮  🕯U+1F57x 🕰  🕱  🕲  🕳  🕴  🕵  🕶  🕷  🕸  🕹      🕻  🕼  🕽  🕾  🕿U+1F58x 🖀  🖁  🖂  🖃  🖄  🖅  🖆  🖇  🖈  🖉  🖊  🖋  🖌  🖍  🖎  🖏U+1F59x 🖐  🖑  🖒  🖓  🖔  🖕  🖖  🖗  🖘  🖙  🖚  🖛  🖜  🖝  🖞  🖟U+1F5Ax 🖠  🖡  🖢  🖣      🖥  🖦  🖧  🖨  🖩  🖪  🖫  🖬  🖭  🖮  🖯U+1F5Bx 🖰  🖱  🖲  🖳  🖴  🖵  🖶  🖷  🖸  🖹  🖺  🖻  🖼  🖽  🖾  🖿U+1F5Cx 🗀  🗁  🗂  🗃  🗄  🗅  🗆  🗇  🗈  🗉  🗊  🗋  🗌  🗍  🗎  🗏U+1F5Dx 🗐  🗑  🗒  🗓  🗔  🗕  🗖  🗗  🗘  🗙  🗚  🗛  🗜  🗝  🗞  🗟U+1F5Ex 🗠  🗡  🗢  🗣  🗤  🗥  🗦  🗧  🗨  🗩  🗪  🗫  🗬  🗭  🗮  🗯U+1F5Fx 🗰  🗱  🗲  🗳  🗴  🗵  🗶  🗷  🗸  🗹  🗺  🗻  🗼  🗽  🗾  🗿",
            "😀 😁  😂  😃  😄  😅  😆  😇  😈  😉  😊  😋  😌  😍  😎  😏U+1F61x 😐  😑  😒  😓  😔  😕  😖  😗  😘  😙  😚  😛  😜  😝  😞  😟U+1F62x 😠  😡  😢  😣  😤  😥  😦  😧  😨  😩  😪  😫  😬  😭  😮  😯U+1F63x 😰  😱  😲  😳  😴  😵  😶  😷  😸  😹  😺  😻  😼  😽  😾  😿U+1F64x 🙀  🙁  🙂          🙅  🙆  🙇  🙈  🙉  🙊  🙋  🙌  🙍  🙎  🙏",
            "🌀🌁🌂🌃🌄🌅🌆🌇🌈🌉🌊🌋🌌🌍🌎🌏🌐🌑🌒🌓🌔🌕🌖🌗🌘🌙🌚🌛🌜🌝🌞🌟🌠 🌰🌱🌲🌳🌴🌵🌷🌸🌹🌺🌻🌼🌽🌾🌿🍀🍁🍂🍃🍄🍅🍆🍇🍈🍉🍊🍋🍌🍍🍎🍏🍐🍑🍒🍓🍔🍕🍖🍗🍘🍙🍚🍛🍜🍝🍞🍟 🍠🍡🍢🍣🍤🍥🍦🍧🍨🍩🍪🍫🍬🍭🍮🍯🍰🍱🍲🍳🍴🍵🍶🍷🍸🍹🍺🍻🍼🎀🎁🎂🎃🎄🎅🎆🎇🎈🎉🎊🎋🎌🎍🎎🎏🎐🎑🎒🎓 🎠🎡🎢🎣🎤🎥🎦🎧🎨🎩🎪🎫🎬🎭🎮🎯🎰🎱🎲🎳🎴🎵🎶🎷🎸🎹🎺🎻🎼🎽🎾🎿🏀🏁🏂🏃🏄🏅🏆🏇🏈🏉🏊 🏠🏡🏢🏣🏤🏥🏦🏧🏨🏩🏪🏫🏬🏭🏮🏯🏰🐀🐁🐂🐃🐄🐅🐆🐇🐈🐉🐊🐋🐌🐍🐎🐏🐐🐑🐒🐓🐔🐕🐖🐗🐘🐙🐚🐛🐜🐝🐞🐟 🐠🐡🐢🐣🐤🐥🐦🐧🐨🐩🐪🐫🐬🐭🐮🐯🐰🐱🐲🐳🐴🐵🐶🐷🐸🐹🐺🐻🐼🐽🐾👀👂👃👄👅👆👇👈👉👊👋👌👍👎👏 👐👑👒👓👔👕👖👗👘👙👚👛👜👝👞👟👠👡👢👣👤👥👦👧👨👩👪👫👬👭👮👯👰👱👲👳👴👵👶👷👸👹👺👻👼👽👾👿 💀💁💂💃💄💅💆💇💈💉💊💋💌💍💎💏💐💑💒💓💔💕💖💘💙💚💛💜💝💞💟💠💡💢💣💤💥💦💧💨💩💪💫💬💭💮💯 💰💱💲💳💴💵💶💷💸💹💺💻💼💽💾💿📀📁📂📃📄📅📆📇📈📉📊📋📌📍📎📏📐📑📒📓📔📕📖📗📘📙📚📛📜📝📞📟 📠📡📢📣📤📥📦📧📨📩📪📫📬📭📮📯📰📱📲📳📴📵📶📷📹📺📻📼🔀🔁🔂🔃🔄🔅🔆🔇🔈🔉🔊🔋🔌🔍🔎🔏 🔐🔑🔒🔓🔔🔕🔖🔗🔘🔙🔚🔛🔜🔝🔞🔟🔠🔡🔢🔣🔤🔥🔦🔧🔨🔩🔪🔫🔬🔭🔮🔯🔰🔱🔲🔳🔴🔵🔶🔷🔸🔹🔺🔻🔼🔽 🕐🕑🕒🕓🕔🕕🕖🕗🕘🕙🕚🕛🕜🕝🕞🕟🕠🕡🕢🕣🕤🕥🕦🕧🗻🗼🗽🗾🗿 😁😂😃😄😅😆😇😈😉😊😋😌😍😎😏😐😒😓😔😖😘😚😜😝😞😠😡😢😣😤😥😨😩😪😫😭😰😱😲😳😵😶😷 😸😹😺😻😼😽😾😿🙀🙅🙆🙇🙈🙉🙊🙋🙌🙍🙎🙏 🚀🚁🚂🚃🚄🚅🚆🚇🚈🚉🚊🚋🚌🚍🚎🚏🚐🚑🚒🚓🚔🚕🚖🚗🚘🚙🚚🚛🚜🚝🚞🚟🚠🚡🚢🚣🚤🚥🚦🚧🚨🚩🚪 🚫🚬🚭🚮🚯🚰🚱🚲🚳🚴🚵🚶🚷🚸🚹🚺🚻🚼🚽🚾🚿🛀🛁🛂🛃🛄🛅",
            "Royal Thai (ราชาศัพท์): (influenced by Khmer) used when addressing members of the royal family or describing their activities. ",
            "טיילאנדיש (ภาษาไทย) איז די באַאַמטער שפּראַך פון טיילאנד און די טייַלענדיש מענטשן. 20,000,000 מענטשן רעדן די שפּראַך, פון זיי -4,700,000 רעדן זי ווי זייער מוטערשפראך.",
            "the Khmer term is ជើងអក្សរ cheung âksâr, meaning \"foot of a letter\"",
            "중화인민공화국에서는 기본적으로 한족은 1명, 일반 소수민족은 2명까지 낳을 수 있지만 3000m 이상의 산지나 고원에서 사는 티베트족은 3명까지 낳을 수 있다",
            "पाठ्यांशः अत्र उपलभ्यतेसर्जनसामान्यलक्षणम्/Share-Alike License; अन्ये नियमाः आन्विताः भवेयुः । दृश्यताम्Terms of use अधिकविवरणाय ।",
            "থাইল্যান্ডের প্রায় ২ কোটি লোকের মাতৃভাষা থাই, যা থাইল্যান্ডের জাতীয় ভাষা। এছাড়া দ্বিতীয় ভাষা হিসেবে আরও প্রায় ২ কোটি লোক আদর্শ থাই ভাষাতে কথা বলতে পারেন। থাইল্যান্ড ছাড়াও মিডওয়ে দ্বীপপুঞ্জ, সিঙ্গাপুর, সংযুক্ত আরব আমিরাত এবং মার্কিন যুক্তরাষ্ট্রে থাই ভাষা প্রচলিত। থাই ভাষাতে \"থাই\" শব্দটির অর্থ \"স্বাধীনতা\"।",
            "திபெத்துக்கு வெளியே வாழும் திபெத்தியர்கள் தெரிவிக்கிறார்கள்",
            "អក្សរសាស្រ្តខែ្មរមានប្រវ៌ត្តជាងពីរពាន់ឆ្នាំមកហើយ ចាប់តាំងពីកំនើតប្រទេសខែ្មរដំបូងមកម្លោះ។ ជនជាតិខែ្មរសម៍យបុរាណបានសំរួលអក្សរខ្មែរមរពីអក្សរសំស្ក្រឹត។",
            "촇֊儠蛸ᣞ㎧贲웆꘠샾䛱郣굉ᵏ椚⣦赢霯⟜㜈幫틃㭯㝻㖎즋鶚宬㑍黡ㆇར렀네𩗗ᄉᄔ嚖蒙⚙摍⨔裔쐬䈇⩌휥㱱蔿⺌ꂤ󌐓쌹᳛쯀汣使ⶓ昌沐꽔⟰錉𨴃⤋冖땀歷皼缔㉚旮쑗匎˺硚鈈ၕ凣碁蜨嬣ᬯ",
            "㢐򇐫큨败奊惆꘤쀉狨㏲㿯뇢縿ꅀ턺䆽靏鱸ꖽ圼І๠㊷槥岾鑨鬦𫭪뵝韻ᒢ覲ڸ巈󡡡虷빉鴟ｵ듷쁼ẓ➱淨㖌甩⦼躂௬ဃ젃扒䠾ㄱ뗄஄䶁늪닫伆牞Ｊ",
    };

    private static final String[] NULL_LINES = {
            "asdf\0\0",
            "\0\0\0\0\0\0\0",
            "asdfasdf\0\0aadsfasdfa\0",
            "\0\0អក្សរសាស្រ្តខែ្មរមានប្រវ៌ត្តជាងពីរពាន់ឆ្នាំមកហើយ",
    };

    @Before
    public void setUp() {
        Logger.getLogger("").setLevel(FINEST);
    }

    @Test
    public void testEstablishedMixedVersionSessionsAliceClientInitiated() throws OtrException {
        final Conversation c = new Conversation(2);

        // Prepare conversation with multiple clients.
        c.clientAlice.setPolicy(new OtrPolicy(ALLOW_V2 | ALLOW_V3 | ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(ALLOW_V3 | ALLOW_V4));
        final LinkedBlockingQueue<String> bob2Channel = new LinkedBlockingQueue<>(2);
        final Client bob2 = new Client("Bob 2", c.sessionIDBob, new OtrPolicy(ALLOW_V2 | ALLOW_V3), c.submitterAlice, bob2Channel);
        c.submitterBob.addQueue(bob2Channel);

        Session.Result result;
        Instance instance;
        
        // Start setting up an encrypted session.
        c.clientAlice.session.startSession();
        // Expecting Query message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertNull(bob2.receiveMessage().content);
        // Expecting Identity message from Bob, DH-Commit message from Bob 2.
        assertNull(c.clientAlice.receiveMessage().content);
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting Auth-R message, DH-Key message from Alice.
        result = c.clientBob.receiveMessage();
        assertNull(result.content);
        instance = c.clientBob.session.getInstance(result.tag);
        assertEquals(ENCRYPTED, instance.getSessionStatus());
        assertEquals(Version.FOUR, instance.getProtocolVersion());
        assertNull(c.clientBob.receiveMessage().content);
        assertNull(bob2.receiveMessage().content);
        assertNull(bob2.receiveMessage().content);
        // Expecting Auth-I message from Bob, Signature message from Bob 2.
        result = c.clientAlice.receiveMessage();
        assertNull(result.content);
        instance = c.clientAlice.session.getInstance(result.tag);
        assertEquals(ENCRYPTED, instance.getSessionStatus());
        result = c.clientAlice.receiveMessage();
        assertNull(result.content);
        instance = c.clientAlice.session.getInstance(bob2.session.getSenderInstanceTag());
        assertEquals(result.tag, bob2.session.getSenderInstanceTag());
        assertEquals(ENCRYPTED, instance.getSessionStatus());
        // Expecting Reveal Signature message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        result = bob2.receiveMessage();
        assertNull(result.content);
        instance = bob2.session.getInstance(result.tag);
        assertEquals(ENCRYPTED, instance.getSessionStatus());
        assertEquals(Version.THREE, instance.getProtocolVersion());

        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientBob.receiptChannel.peek()));
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        assertTrue(otrEncoded(bob2.receiptChannel.peek()));
        assertEquals(msg1, c.clientBob.receiveMessage().content);
        assertNull(bob2.receiveMessage().content);
        c.clientAlice.sendMessage(bob2.session.getSenderInstanceTag(), msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientBob.receiptChannel.peek()));
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        assertTrue(otrEncoded(bob2.receiptChannel.peek()));
        assertEquals(msg1, bob2.receiveMessage().content);
        assertNull(c.clientBob.receiveMessage().content);

        assertEquals(0, c.clientAlice.receiptChannel.size());
        assertEquals(0, c.clientBob.receiptChannel.size());
        assertEquals(0, bob2.receiptChannel.size());
    }

    @Test
    public void testEstablishedMixedVersionSessionsAliceClientInitiatedFragmented() throws OtrException, ProtocolException {
        final Random random = createDeterministicRandom(RANDOM.nextLong());
        final Conversation c = new Conversation(MAX_VALUE, 150);

        // Prepare conversation with multiple clients.
        c.clientAlice.setPolicy(new OtrPolicy(ALLOW_V2 | ALLOW_V3 | ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(ALLOW_V3 | ALLOW_V4));
        final LinkedBlockingQueue<String> bob2Channel = new LinkedBlockingQueue<>(MAX_VALUE);
        final Client bob2 = new Client("Bob 2", c.sessionIDBob, new OtrPolicy(ALLOW_V2 | ALLOW_V3), c.submitterAlice, bob2Channel);
        bob2.setMessageSize(150);
        c.submitterBob.addQueue(bob2Channel);

        Instance instance;

        // Start setting up an encrypted session.
        c.clientAlice.session.startSession();
        // Expecting Query message from Alice.
        rearrangeFragments(c.clientBob.receiptChannel, random);
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        rearrangeFragments(bob2.receiptChannel, random);
        assertArrayEquals(new String[0], bob2.receiveAllMessages(true));
        // Expecting Identity message from Bob, DH-Commit message from Bob 2.
        rearrangeFragments(c.clientAlice.receiptChannel, random);
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        // Expecting Auth-R message, DH-Key message from Alice.
        rearrangeFragments(c.clientBob.receiptChannel, random);
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        instance = c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag());
        assertEquals(ENCRYPTED, instance.getSessionStatus());
        assertEquals(Version.FOUR, instance.getProtocolVersion());
        rearrangeFragments(bob2.receiptChannel, random);
        assertArrayEquals(new String[0], bob2.receiveAllMessages(true));
        // Expecting Auth-I message from Bob, Signature message from Bob 2.
        rearrangeFragments(c.clientAlice.receiptChannel, random);
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(bob2.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting DAKE data message, Reveal Signature message from Alice.
        rearrangeFragments(c.clientBob.receiptChannel, random);
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        rearrangeFragments(bob2.receiptChannel, random);
        assertArrayEquals(new String[0], bob2.receiveAllMessages(true));
        instance = bob2.session.getInstance(c.clientAlice.session.getSenderInstanceTag());
        assertEquals(ENCRYPTED, instance.getSessionStatus());
        assertEquals(Version.THREE, instance.getProtocolVersion());

        // Due to 2 sessions being set up at the same time, either one can be established first. The first session is
        // automatically chosen to be the default session, so we need to manually set our chosen session as default
        // outgoing session.
        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertTrue(otrFragmented(c.clientBob.receiptChannel.peek()));
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        assertTrue(otrFragmented(bob2.receiptChannel.peek()));
        rearrangeFragments(c.clientBob.receiptChannel, random);
        assertArrayEquals(new String[] {msg1}, c.clientBob.receiveAllMessages(true));
        rearrangeFragments(bob2.receiptChannel, random);
        assertArrayEquals(new String[0], bob2.receiveAllMessages(true));
        c.clientAlice.sendMessage(bob2.session.getSenderInstanceTag(), msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertTrue(otrFragmented(c.clientBob.receiptChannel.peek()));
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        assertTrue(otrFragmented(bob2.receiptChannel.peek()));
        rearrangeFragments(bob2.receiptChannel, random);
        assertArrayEquals(new String[] {msg1}, bob2.receiveAllMessages(true));
        rearrangeFragments(c.clientBob.receiptChannel, random);
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));

        assertEquals(0, c.clientAlice.receiptChannel.size());
        assertEquals(0, c.clientBob.receiptChannel.size());
        assertEquals(0, bob2.receiptChannel.size());
    }

    @Test
    public void testEstablishedMixedVersionSessionsBobsClientInitiates() throws OtrException {
        final Conversation c = new Conversation(2);

        // Prepare conversation with multiple clients.
        c.clientAlice.setPolicy(new OtrPolicy(ALLOW_V2 | ALLOW_V3 | ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(ALLOW_V2 | ALLOW_V3));
        final LinkedBlockingQueue<String> bob2Channel = new LinkedBlockingQueue<>(2);
        final Client bob2 = new Client("Bob 2", c.sessionIDBob, new OtrPolicy(ALLOW_V3 | ALLOW_V4), c.submitterAlice, bob2Channel);
        c.submitterBob.addQueue(bob2Channel);

        Instance instance;

        // Start setting up an encrypted session.
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, OTRv23QueryMessage);
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting DH-Commit message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertNull(bob2.receiveMessage().content);
        // Expecting DH-Key message from both of Bob's clients.
        assertNull(c.clientAlice.receiveMessage().content);
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting Signature message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertNull(c.clientBob.receiveMessage().content);
        assertNull(bob2.receiveMessage().content);
        assertNull(bob2.receiveMessage().content);
        instance = c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag());
        assertEquals(ENCRYPTED, instance.getSessionStatus());
        assertEquals(Version.THREE, instance.getProtocolVersion());
        instance = bob2.session.getInstance(c.clientAlice.session.getSenderInstanceTag());
        assertEquals(ENCRYPTED, instance.getSessionStatus());
        // TODO there is an issue with the OTR protocol such that acting on a received DH-Commit message skips the check of whether higher versions of the OTR protocol are available. (Consider not responding unless a query tag was previously sent.)
        assertEquals(Version.THREE, instance.getProtocolVersion());
        // Expecting Reveal Signature message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(bob2.session.getSenderInstanceTag()).getSessionStatus());

        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientBob.receiptChannel.peek()));
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        assertTrue(otrEncoded(bob2.receiptChannel.peek()));
        assertEquals(msg1, c.clientBob.receiveMessage().content);
        assertNull(bob2.receiveMessage().content);
    }

    @Test
    public void testMultipleSessions() throws OtrException {
        final OtrPolicy policy = new OtrPolicy(ALLOW_V2 | ALLOW_V3 | ERROR_START_AKE);
        final Conversation c = new Conversation(3);

        // Prepare conversation with multiple clients.
        c.clientAlice.setPolicy(policy);
        c.clientBob.setPolicy(policy);
        final LinkedBlockingQueue<String> bob2Channel = new LinkedBlockingQueue<>(3);
        final Client bob2 = new Client("Bob 2", c.sessionIDBob, policy, c.submitterAlice, bob2Channel);
        c.submitterBob.addQueue(bob2Channel);
        final LinkedBlockingQueue<String> bob3Channel = new LinkedBlockingQueue<>(3);
        final Client bob3 = new Client("Bob 3", c.sessionIDBob, policy, c.submitterAlice, bob3Channel);
        c.submitterBob.addQueue(bob3Channel);

        // Start setting up an encrypted session.
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, OTRv23QueryMessage);
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting DH-Commit message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertNull(bob2.receiveMessage().content);
        assertNull(bob3.receiveMessage().content);
        // Expecting DH-Key message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertNull(c.clientAlice.receiveMessage().content);
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting Signature message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertNull(c.clientBob.receiveMessage().content);
        assertNull(c.clientBob.receiveMessage().content);
        assertNull(bob2.receiveMessage().content);
        assertNull(bob2.receiveMessage().content);
        assertNull(bob2.receiveMessage().content);
        assertNull(bob3.receiveMessage().content);
        assertNull(bob3.receiveMessage().content);
        assertNull(bob3.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(ENCRYPTED, bob2.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(ENCRYPTED, bob3.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting Reveal Signature message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertNull(c.clientAlice.receiveMessage().content);
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(bob2.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(bob3.session.getSenderInstanceTag()).getSessionStatus());

        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientBob.receiptChannel.peek()));
        assertNotEquals(msg1, bob2.receiptChannel.peek());
        assertTrue(otrEncoded(bob2.receiptChannel.peek()));
        assertNotEquals(msg1, bob3.receiptChannel.peek());
        assertTrue(otrEncoded(bob3.receiptChannel.peek()));
        assertEquals(msg1, c.clientBob.receiveMessage().content);
        assertNull(bob2.receiveMessage().content);
        assertNull(bob3.receiveMessage().content);

        // Continue conversation with first of Bob's clients.
        final String msg2 = "Hey Alice, it means that our communication is encrypted and authenticated.";
        c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), msg2);
        assertNotEquals(msg2, c.clientAlice.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientAlice.receiptChannel.peek()));
        assertEquals(msg2, c.clientAlice.receiveMessage().content);

        final String msg3 = "Oh, is that all?";
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), msg3);
        assertNotEquals(msg3, c.clientBob.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientBob.receiptChannel.peek()));
        assertNotEquals(msg3, bob2.receiptChannel.peek());
        assertTrue(otrEncoded(bob2.receiptChannel.peek()));
        assertNotEquals(msg3, bob3.receiptChannel.peek());
        assertTrue(otrEncoded(bob3.receiptChannel.peek()));
        assertEquals(msg3, c.clientBob.receiveMessage().content);
        assertNull(bob2.receiveMessage().content);
        assertNull(bob3.receiveMessage().content);

        final String msg4 = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.";
        c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), msg4);
        assertNotEquals(msg4, c.clientAlice.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientAlice.receiptChannel.peek()));
        assertEquals(msg4, c.clientAlice.receiveMessage().content);

        final String msg5 = "Oh really?! pouvons-nous parler en français?";
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), msg5);
        assertNotEquals(msg5, c.clientBob.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientBob.receiptChannel.peek()));
        assertNotEquals(msg5, bob2.receiptChannel.peek());
        assertTrue(otrEncoded(bob2.receiptChannel.peek()));
        assertNotEquals(msg5, bob3.receiptChannel.peek());
        assertTrue(otrEncoded(bob3.receiptChannel.peek()));
        assertEquals(msg5, c.clientBob.receiveMessage().content);
        assertNull(bob2.receiveMessage().content);
        assertNull(bob3.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).endSession();
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(FINISHED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(ENCRYPTED, bob2.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(ENCRYPTED, bob3.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());

        assertEquals(0, c.clientAlice.receiptChannel.size());
        assertEquals(0, c.clientBob.receiptChannel.size());
        assertEquals(0, bob2.receiptChannel.size());
        assertEquals(0, bob3.receiptChannel.size());
    }

    @Test
    public void testQueryStart() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientAlice.setPolicy(new OtrPolicy(OPPORTUNISTIC & ~ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(OPPORTUNISTIC & ~ALLOW_V4));
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, OTRv23QueryMessage);
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting DH-Commit message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting DH-Key message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting Signature message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting Reveal Signature message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientBob.receiptChannel.peek()));
        assertEquals(msg1, c.clientBob.receiveMessage().content);
        final String msg2 = "Hey Alice, it means that our communication is encrypted and authenticated.";
        c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), msg2);
        assertNotEquals(msg2, c.clientAlice.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientAlice.receiptChannel.peek()));
        assertEquals(msg2, c.clientAlice.receiveMessage().content);
        final String msg3 = "Oh, is that all?";
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), msg3);
        assertNotEquals(msg3, c.clientBob.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientBob.receiptChannel.peek()));
        assertEquals(msg3, c.clientBob.receiveMessage().content);
        final String msg4 = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.";
        c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), msg4);
        assertNotEquals(msg4, c.clientAlice.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientAlice.receiptChannel.peek()));
        assertEquals(msg4, c.clientAlice.receiveMessage().content);
        final String msg5 = "Oh really?! pouvons-nous parler en français?";
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), msg5);
        assertNotEquals(msg5, c.clientBob.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientBob.receiptChannel.peek()));
        assertEquals(msg5, c.clientBob.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).endSession();
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        // Bob has not yet switched session status as he has not processed the message yet.
        assertEquals(PLAINTEXT, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
    }

    @Test
    public void testForcedStart() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientAlice.setPolicy(new OtrPolicy(OTRL_POLICY_MANUAL & ~ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(OTRL_POLICY_MANUAL & ~ALLOW_V4));
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, "Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage().content);
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting DH-Commit message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting DH-Key message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Signature message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting Reveal Signature message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), msg1);
        assertNotEquals(msg1, c.clientBob.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientBob.receiptChannel.peek()));
        assertEquals(msg1, c.clientBob.receiveMessage().content);
        final String msg2 = "Hey Alice, it means that our communication is encrypted and authenticated.";
        c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), msg2);
        assertNotEquals(msg2, c.clientAlice.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientAlice.receiptChannel.peek()));
        assertEquals(msg2, c.clientAlice.receiveMessage().content);
        final String msg3 = "Oh, is that all?";
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), msg3);
        assertNotEquals(msg3, c.clientBob.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientBob.receiptChannel.peek()));
        assertEquals(msg3, c.clientBob.receiveMessage().content);
        final String msg4 = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.";
        c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), msg4);
        assertNotEquals(msg4, c.clientAlice.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientAlice.receiptChannel.peek()));
        assertEquals(msg4, c.clientAlice.receiveMessage().content);
        final String msg5 = "Oh really?! pouvons-nous parler en français?";
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), msg5);
        assertNotEquals(msg5, c.clientBob.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientBob.receiptChannel.peek()));
        assertEquals(msg5, c.clientBob.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).endSession();
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        // Bob has not yet switched session status as he has not processed the message yet.
        assertEquals(PLAINTEXT, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
    }

    @Test
    public void testPlaintext() throws OtrException {
        final Conversation c = new Conversation(1);
        final String msg1 = "Hello Bob, this new IM software you installed on my PC the other day says we are talking Off-the-Record, what's that supposed to mean?";
        c.clientAlice.sendMessage(InstanceTag.ZERO_TAG, msg1);
        assertEquals(msg1, c.clientBob.receiveMessage().content);
        assertEquals(PLAINTEXT, c.clientAlice.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
        final String msg2 = "Hey Alice, it means that our communication is encrypted and authenticated.";
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, msg2);
        assertEquals(msg2, c.clientAlice.receiveMessage().content);
        assertEquals(PLAINTEXT, c.clientAlice.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
        final String msg3 = "Oh, is that all?";
        c.clientAlice.sendMessage(InstanceTag.ZERO_TAG, msg3);
        assertEquals(msg3, c.clientBob.receiveMessage().content);
        assertEquals(PLAINTEXT, c.clientAlice.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
        final String msg4 = "Actually no, our communication has the properties of perfect forward secrecy and deniable authentication.";
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, msg4);
        assertEquals(msg4, c.clientAlice.receiveMessage().content);
        assertEquals(PLAINTEXT, c.clientAlice.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
        final String msg5 = "Oh really?! pouvons-nous parler en français?";
        c.clientAlice.sendMessage(InstanceTag.ZERO_TAG, msg5);
        assertEquals(msg5, c.clientBob.receiveMessage().content);
        assertEquals(PLAINTEXT, c.clientAlice.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
        c.clientBob.session.getInstance(InstanceTag.ZERO_TAG).endSession();
        c.clientAlice.session.getInstance(InstanceTag.ZERO_TAG).endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
        assertEquals(PLAINTEXT, c.clientBob.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
    }

    @Test
    public void testPlainTextMessagingNewClients() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, "hello world");
        assertEquals("hello world", c.clientAlice.receiveMessage().content);
        c.clientAlice.sendMessage(InstanceTag.ZERO_TAG, "hello bob");
        assertEquals("hello bob", c.clientBob.receiveMessage().content);
    }

    @Test
    public void testUnicodeMessagesInPlainTextSession() throws OtrException {
        final Conversation c = new Conversation(2);
        for (final String message : UNICODE_LINES) {
            assertEquals(SessionStatus.PLAINTEXT, c.clientAlice.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
            c.clientAlice.sendMessage(InstanceTag.ZERO_TAG, message);
            assertEquals(message, c.clientBob.receiptChannel.peek());
            final Session.Result receivedBob = c.clientBob.receiveMessage();
            assertEquals(SessionStatus.PLAINTEXT, c.clientBob.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
            assertEquals(SessionStatus.PLAINTEXT, receivedBob.status);
            assertEquals(message, receivedBob.content);

            assertEquals(SessionStatus.PLAINTEXT, c.clientBob.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
            c.clientBob.sendMessage(InstanceTag.ZERO_TAG, message);
            assertEquals(message, c.clientAlice.receiptChannel.peek());
            final Session.Result receivedAlice = c.clientAlice.receiveMessage();
            assertEquals(SessionStatus.PLAINTEXT, c.clientAlice.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
            assertEquals(SessionStatus.PLAINTEXT, receivedAlice.status);
            assertEquals(message, receivedAlice.content);
        }
    }

    @Test
    public void testNullLinesInPlainTextSession() throws OtrException {
        final Conversation c = new Conversation(2);
        for (final String line : NULL_LINES) {
            assertEquals(SessionStatus.PLAINTEXT, c.clientAlice.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
            c.clientAlice.sendMessage(InstanceTag.ZERO_TAG, line);
            assertEquals(line, c.clientBob.receiptChannel.peek());
            final Session.Result receivedBob = c.clientBob.receiveMessage();
            assertEquals(SessionStatus.PLAINTEXT, c.clientBob.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
            assertEquals(SessionStatus.PLAINTEXT, receivedBob.status);
            assertEquals(line, receivedBob.content);

            assertEquals(SessionStatus.PLAINTEXT, c.clientBob.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
            c.clientBob.sendMessage(InstanceTag.ZERO_TAG, line);
            assertEquals(line, c.clientAlice.receiptChannel.peek());
            final Session.Result receivedAlice = c.clientAlice.receiveMessage();
            assertEquals(SessionStatus.PLAINTEXT, c.clientAlice.session.getInstance(InstanceTag.ZERO_TAG).getSessionStatus());
            assertEquals(SessionStatus.PLAINTEXT, receivedAlice.status);
            assertEquals(line, receivedAlice.content);
        }
    }

    @Test
    public void testNullLinesInEncryptedSession() throws OtrException {
        final Conversation c = new Conversation(2);
        c.clientAlice.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V4));
        c.clientAlice.session.startSession();
        c.clientBob.receiveMessage();
        c.clientAlice.receiveMessage();
        c.clientBob.receiveMessage();
        assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        c.clientAlice.receiveMessage();
        assertEquals(SessionStatus.ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        for (final String line : NULL_LINES) {
            c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), line);
            final String sanitizedLine = line.replace('\0', '?');
            assertNotEquals(sanitizedLine, c.clientBob.receiptChannel.peek());
            assertTrue(otrEncoded(c.clientBob.receiptChannel.peek()));
            final Session.Result receivedBob = c.clientBob.receiveMessage();
            assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
            assertEquals(SessionStatus.ENCRYPTED, receivedBob.status);
            assertEquals(sanitizedLine, receivedBob.content);

            c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), line);
            assertNotEquals(sanitizedLine, c.clientAlice.receiptChannel.peek());
            assertTrue(otrEncoded(c.clientAlice.receiptChannel.peek()));
            final Session.Result receivedAlice = c.clientAlice.receiveMessage();
            assertEquals(SessionStatus.ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
            assertEquals(SessionStatus.ENCRYPTED, receivedAlice.status);
            assertEquals(sanitizedLine, receivedAlice.content);
        }
    }

    @Test
    public void testUnicodeMessagesInEncryptedSession() throws OtrException {
        final Conversation c = new Conversation(2);
        c.clientAlice.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V4));
        c.clientBob.setPolicy(new OtrPolicy(OtrPolicy.ALLOW_V4));
        c.clientAlice.session.startSession();
        c.clientBob.receiveMessage();
        c.clientAlice.receiveMessage();
        c.clientBob.receiveMessage();
        assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        c.clientAlice.receiveMessage();
        assertEquals(SessionStatus.ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        for (final String message : UNICODE_LINES) {
            c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), message);
            assertNotEquals(message, c.clientBob.receiptChannel.peek());
            assertTrue(otrEncoded(c.clientBob.receiptChannel.peek()));
            final Session.Result receivedBob = c.clientBob.receiveMessage();
            assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
            assertEquals(SessionStatus.ENCRYPTED, receivedBob.status);
            assertEquals(message, receivedBob.content);

            assertEquals(SessionStatus.ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
            c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), message);
            assertNotEquals(message, c.clientAlice.receiptChannel.peek());
            assertTrue(otrEncoded(c.clientAlice.receiptChannel.peek()));
            final Session.Result receivedAlice = c.clientAlice.receiveMessage();
            assertEquals(SessionStatus.ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
            assertEquals(SessionStatus.ENCRYPTED, receivedAlice.status);
            assertEquals(message, receivedAlice.content);
        }
        c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).endSession();
        assertEquals(SessionStatus.PLAINTEXT, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        c.clientAlice.receiveMessage();
        assertEquals(SessionStatus.FINISHED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).endSession();
        assertEquals(SessionStatus.PLAINTEXT, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
    }

    @Test
    public void testEstablishOTR4Session() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, "Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage().content);
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        // Start sending messages
        c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), "Hello Alice!");
        assertNotEquals("Hello Alice!", c.clientAlice.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientAlice.receiptChannel.peek()));
        assertEquals("Hello Alice!", c.clientAlice.receiveMessage().content);
        c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(FINISHED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
    }

    @Test
    public void testEstablishOTR4SessionEarlyMessaging() throws OtrException {
        final Conversation c = new Conversation(3);
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, "Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage().content);
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), "Bob's early message 1");
        c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), "Bob's early message 2");
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), "Alice's early message 1");
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), "Alice's early message 2");
        // Start sending messages
        assertEquals("Bob's early message 1", c.clientAlice.receiveMessage().content);
        assertEquals("Bob's early message 2", c.clientAlice.receiveMessage().content);
        assertEquals("Alice's early message 1", c.clientBob.receiveMessage().content);
        assertEquals("Alice's early message 2", c.clientBob.receiveMessage().content);
        c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), "Hello Alice, I got your messages.");
        assertEquals("Hello Alice, I got your messages.", c.clientAlice.receiveMessage().content);
        assertEquals(0, c.clientBob.receiptChannel.size());
        assertEquals(0, c.clientAlice.receiptChannel.size());
        c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(FINISHED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
    }

    @Test
    public void testEstablishOTR4SessionEarlyMessagingOutOfOrder() throws OtrException {
        final Conversation c = new Conversation(3);
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, "Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage().content);
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), "Bob's early message 1");
        c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), "Bob's early message 2");

        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), "Alice's early message 1");
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), "Alice's early message 2");
        // Receive messages out-of-order.
        c.clientAlice.receiptChannel.add(c.clientAlice.receiptChannel.remove());
        assertEquals("Bob's early message 2", c.clientAlice.receiveMessage().content);
        assertEquals("Bob's early message 1", c.clientAlice.receiveMessage().content);
        c.clientBob.receiptChannel.add(c.clientBob.receiptChannel.remove());
        assertEquals("Alice's early message 2", c.clientBob.receiveMessage().content);
        assertEquals("Alice's early message 1", c.clientBob.receiveMessage().content);
        c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), "Hello Alice, I got your messages.");
        assertEquals("Hello Alice, I got your messages.", c.clientAlice.receiveMessage().content);
        assertEquals(0, c.clientBob.receiptChannel.size());
        assertEquals(0, c.clientAlice.receiptChannel.size());
        c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(FINISHED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
    }

    @Test
    public void testEstablishOTR4SessionThenDisallowSendingQueryMessage() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, "Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage().content);
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        // Start sending messages
        c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), "Hello Alice!");
        assertNotEquals("Hello Alice!", c.clientAlice.receiptChannel.peek());
        assertTrue(otrEncoded(c.clientAlice.receiptChannel.peek()));
        assertEquals("Hello Alice!", c.clientAlice.receiveMessage().content);
        // Even though encrypted now, start a new session. This should not follow through.
        c.clientBob.session.startSession();
        assertFalse(c.clientAlice.receiptChannel.isEmpty());
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).endSession();
        assertEquals(PLAINTEXT, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(FINISHED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
    }

    @Test
    public void testEstablishOTR4SessionFragmented() throws OtrException {
        final Conversation c = new Conversation(21, 150,
                new OtrPolicy(ALLOW_V4 | WHITESPACE_START_AKE | ERROR_START_AKE));
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, "Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage().content);
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Identity message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        // Expecting AUTH_R message from Alice.
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
    }

    @Test
    public void testEstablishOTR4SessionFragmentedMessageFragmentDropped() throws OtrException {
        final Random random = createDeterministicRandom(RANDOM.nextLong());
        final Conversation c = new Conversation(21, 150,
                new OtrPolicy(ALLOW_V4 | WHITESPACE_START_AKE | ERROR_START_AKE));
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, "Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage().content);
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Identity message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        // Expecting AUTH_R message from Alice.
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        assertTrue(c.clientAlice.receiptChannel.isEmpty());
        assertTrue(c.clientBob.receiptChannel.isEmpty());
        // Start of confidential conversation.
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), "Hello Bob!");
        assertNotEquals("Hello Bob!", c.clientBob.receiptChannel.peek());
        assertTrue(otrFragmented(c.clientBob.receiptChannel.peek()));
        assertArrayEquals(new String[] {"Hello Bob!"}, c.clientBob.receiveAllMessages(true));
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), "Hello Bob - this messages gets partially dropped ............................");
        drop(new int[] {random.nextInt(4)}, c.clientBob.receiptChannel);
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), "You should be able to receive this message.");
        assertArrayEquals(new String[] {"You should be able to receive this message."}, c.clientBob.receiveAllMessages(true));
    }

    @Test
    public void testOTR4ExtensiveMessagingToVerifyRatcheting() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, "Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage().content);
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());

        final Random random = createDeterministicRandom(RANDOM.nextLong());
        for (int i = 0; i < 25; i++) {
            // Bob sending a message (alternating, to enable ratchet)
            final String messageBob = randomMessage(random, 300);
            c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), messageBob);
            assertMessage("Iteration: " + i + ", message Bob: " + messageBob, messageBob, c.clientAlice.receiveMessage().content);
            // Alice sending a message (alternating, to enable ratchet)
            final String messageAlice = randomMessage(random, 300);
            c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), messageAlice);
            assertMessage("Iteration: " + i + ", message Alice: " + messageAlice, messageAlice, c.clientBob.receiveMessage().content);
        }
    }

    @Test
    public void testOTR4ExtensiveMessagingToVerifyRatchetingManyConsecutiveMessages() throws OtrException {
        final Conversation c = new Conversation(25);
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, "Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage().content);
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());

        final Random random = createDeterministicRandom(RANDOM.nextLong());
        final String[] messages = new String[25];
        for (int i = 0; i < messages.length; i++) {
            messages[i] = randomMessage(random, 300);
        }
        // Bob sending many messages
        for (final String message : messages) {
            c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), message);
        }
        for (final String message : messages) {
            assertMessage("Message Bob: " + message, message, c.clientAlice.receiveMessage().content);
        }
        // Alice sending one message in response
        final String messageAlice = "Man, you talk a lot!";
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), messageAlice);
        assertMessage("Message Alice: " + messageAlice, messageAlice, c.clientBob.receiveMessage().content);
    }

    @Test
    public void testOTR4ExtensiveMessagingManyConsecutiveMessagesIncidentallyDropped() throws OtrException {
        final Conversation c = new Conversation(25);
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, "Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage().content);
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());

        final Random random = createDeterministicRandom(RANDOM.nextLong());
        final String[] messages = new String[25];
        for (int i = 0; i < messages.length; i++) {
            messages[i] = randomMessage(random, 300);
        }
        // Bob sending many messages
        for (final String message : messages) {
            c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), message);
        }
        // Determine three messages to drop. Avoid dropping first message as this is a known limitation that cannot be
        // mitigated.
        final int drop1 = random.nextInt(messages.length - 1) + 1;
        final int drop2 = random.nextInt(messages.length - 1) + 1;
        final int drop3 = random.nextInt(messages.length - 1) + 1;
        drop(new int[] {drop1, drop2, drop3}, c.clientAlice.receiptChannel);
        for (int i = 0; i < messages.length; i++) {
            if (i == drop1 || i == drop2 || i == drop3) {
                continue;
            }
            assertMessage("Message Bob: " + messages[i], messages[i], c.clientAlice.receiveMessage().content);
        }
        // Alice sending one message in response
        final String messageAlice = "Man, you talk a lot!";
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), messageAlice);
        assertMessage("Message Alice: " + messageAlice, messageAlice, c.clientBob.receiveMessage().content);
    }

    @Test
    public void testOTR4ExtensiveMessagingManyConsecutiveMessagesShuffled() throws OtrException {
        final Conversation c = new Conversation(25);
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, "Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage().content);
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());

        final Random random = createDeterministicRandom(RANDOM.nextLong());
        final String[] messages = new String[25];
        for (int i = 0; i < messages.length; i++) {
            messages[i] = randomMessage(random, 300);
        }
        // Bob sending many messages
        for (final String message : messages) {
            c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), message);
        }
        shuffle(c.clientAlice.receiptChannel, random);
        final HashSet<String> receivedMessages = new HashSet<>();
        for (int i = 0; i < messages.length; i++) {
            System.err.println("Message " + i);
            final Session.Result result = c.clientAlice.receiveMessage();
            final String received = result.content;
            if (!contains(received, messages)) {
                fail("Expected message to be present in the list of sent messages: " + received);
            }
            receivedMessages.add(received);
        }
        assertEquals(messages.length, receivedMessages.size());
        // Alice sending one message in response
        final String messageAlice = "Man, you talk a lot!";
        c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), messageAlice);
        assertMessage("Message Alice: " + messageAlice, messageAlice, c.clientBob.receiveMessage().content);
        c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).endSession();
        c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).endSession();
    }

    @Test
    public void testOTR4SessionWithSMPGoodPassword() throws OtrException {
        final Conversation c = new Conversation(1);

        assertTrue(c.clientAlice.verified.isEmpty());
        assertTrue(c.clientBob.verified.isEmpty());

        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());

        // Initiate SMP negotiation
        final Instance instanceBob = c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag());
        assertFalse(instanceBob.isSmpInProgress());
        final Instance instanceAlice = c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag());
        assertFalse(instanceAlice.isSmpInProgress());
        instanceBob.initSmp("What's the secret?", "Nobody knows!");
        assertTrue(instanceBob.isSmpInProgress());
        assertFalse(instanceAlice.isSmpInProgress());

        assertNull(c.clientAlice.receiveMessage().content);
        instanceAlice.respondSmp("What's the secret?", "Nobody knows!");
        assertTrue(instanceBob.isSmpInProgress());
        assertTrue(instanceAlice.isSmpInProgress());

        assertNull(c.clientBob.receiveMessage().content);
        assertTrue(instanceBob.isSmpInProgress());
        assertTrue(instanceAlice.isSmpInProgress());

        assertNull(c.clientAlice.receiveMessage().content);
        assertTrue(instanceBob.isSmpInProgress());
        assertFalse(instanceAlice.isSmpInProgress());

        assertNull(c.clientBob.receiveMessage().content);
        assertFalse(instanceBob.isSmpInProgress());
        assertFalse(instanceAlice.isSmpInProgress());

        assertEquals(1, c.clientAlice.verified.size());
        assertEquals(1, c.clientBob.verified.size());
    }

    @Test
    public void testOTR4SessionWithSMPBadPassword() throws OtrException {
        final Conversation c = new Conversation(1);

        assertTrue(c.clientAlice.verified.isEmpty());
        assertTrue(c.clientBob.verified.isEmpty());

        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());

        // Initiate SMP negotiation
        final Instance instanceBob = c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag());
        instanceBob.initSmp("What's the secret?", "Nobody knows!");
        assertTrue(instanceBob.isSmpInProgress());
        assertNull(c.clientAlice.receiveMessage().content);
        final Instance instanceAlice = c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag());
        instanceAlice.respondSmp("What's the secret?", "Everybody knows!");
        assertTrue(instanceAlice.isSmpInProgress());
        assertNull(c.clientBob.receiveMessage().content);
        assertTrue(instanceAlice.isSmpInProgress());
        assertNull(c.clientAlice.receiveMessage().content);
        assertFalse(instanceAlice.isSmpInProgress());
        assertTrue(instanceBob.isSmpInProgress());
        assertNull(c.clientBob.receiveMessage().content);
        assertFalse(instanceBob.isSmpInProgress());

        assertTrue(c.clientAlice.verified.isEmpty());
        assertTrue(c.clientBob.verified.isEmpty());
    }

    @Test
    public void testOTR4SessionWithSMPUnicodeTests() throws OtrException {
        final Conversation c = new Conversation(1);
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());

        final Instance instanceBob = c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag());
        final Instance instanceAlice = c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag());

        for (int i = 0; i < UNICODE_LINES.length; ++i) {
            c.clientBob.verified.clear();
            c.clientAlice.verified.clear();

            // Initiate SMP negotiation
            instanceBob.initSmp(UNICODE_LINES[i], UNICODE_LINES[UNICODE_LINES.length - 1 - i]);
            assertTrue(instanceBob.isSmpInProgress());
            assertNull(c.clientAlice.receiveMessage().content);
            instanceAlice.respondSmp(UNICODE_LINES[i], UNICODE_LINES[UNICODE_LINES.length - 1 - i]);
            assertTrue(instanceAlice.isSmpInProgress());
            assertNull(c.clientBob.receiveMessage().content);
            assertTrue(instanceAlice.isSmpInProgress());
            assertNull(c.clientAlice.receiveMessage().content);
            assertFalse(instanceAlice.isSmpInProgress());
            assertTrue(instanceBob.isSmpInProgress());
            assertNull(c.clientBob.receiveMessage().content);
            assertFalse(instanceBob.isSmpInProgress());

            assertEquals(1, c.clientBob.verified.size());
            assertEquals(1, c.clientAlice.verified.size());
        }
    }

    @Test
    public void testOTR4ExtensiveMessagingFragmentation() throws OtrException {
        final Conversation c = new Conversation(21, 150,
                new OtrPolicy(ALLOW_V4 | WHITESPACE_START_AKE | ERROR_START_AKE));
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, "Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage().content);
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Identity message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        // Expecting AUTH_R message from Alice.
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());

        final Random random = createDeterministicRandom(RANDOM.nextLong());
        for (int i = 0; i < 25; i++) {
            // Bob sending a message (alternating, to enable ratchet)
            final String messageBob = randomMessage(random, 1, 500);
            c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), messageBob);
            assertArrayEquals("Iteration: " + i + ", message Bob: " + messageBob,
                    new String[] {messageBob}, c.clientAlice.receiveAllMessages(true));
            // Alice sending a message (alternating, to enable ratchet)
            final String messageAlice = randomMessage(random, 1, 500);
            c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), messageAlice);
            assertArrayEquals("Iteration: " + i + ", message Alice: " + messageAlice,
                    new String[] {messageAlice}, c.clientBob.receiveAllMessages(true));
        }
    }

    @Test
    public void testOTR4ExtensiveMessagingFragmentationShuffled() throws OtrException {
        final Random random = createDeterministicRandom(RANDOM.nextLong());
        final Conversation c = new Conversation(21, 150,
                new OtrPolicy(ALLOW_V4 | WHITESPACE_START_AKE | ERROR_START_AKE));
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, "Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage().content);
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Identity message from Bob.
        shuffle(c.clientAlice.receiptChannel, random);
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        // Expecting AUTH_R message from Alice.
        shuffle(c.clientBob.receiptChannel, random);
        assertArrayEquals(new String[0], c.clientBob.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting AUTH_I message from Bob.
        shuffle(c.clientAlice.receiptChannel, random);
        assertArrayEquals(new String[0], c.clientAlice.receiveAllMessages(true));
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting heartbeat message from Alice to enable Bob to complete the Double Ratchet initialization.
        shuffle(c.clientBob.receiptChannel, random);
        assertEquals(0, c.clientBob.receiveAllMessages(true).length);

        for (int i = 0; i < 25; i++) {
            // Bob sending a message (alternating, to enable ratchet)
            final String messageBob = randomMessage(random, 1, 500);
            c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), messageBob);
            shuffle(c.clientAlice.receiptChannel, random);
            assertArrayEquals("Iteration: " + i + ", message Bob: " + messageBob,
                    new String[] {messageBob}, c.clientAlice.receiveAllMessages(true));
            // Alice sending a message (alternating, to enable ratchet)
            final String messageAlice = randomMessage(random, 1, 500);
            c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), messageAlice);
            shuffle(c.clientBob.receiptChannel, random);
            assertArrayEquals("Iteration: " + i + ", message Alice: " + messageAlice,
                    new String[] {messageAlice}, c.clientBob.receiveAllMessages(true));
        }
    }

    @Test
    public void testOTR4SmallConversationWithHugeMessages() throws OtrException {
        final Conversation c = new Conversation(1);
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, "Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage().content);
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());

        final Random random = createDeterministicRandom(RANDOM.nextLong());
        for (int i = 0; i < 5; i++) {
            // Bob sending a message (alternating, to enable ratchet)
            final String messageBob = randomMessage(random, 1000000);
            c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), messageBob);
            assertMessage("Iteration: " + i + ", message Bob: " + messageBob, messageBob, c.clientAlice.receiveMessage().content);
            // Alice sending a message (alternating, to enable ratchet)
            final String messageAlice = randomMessage(random, 1000000);
            c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), messageAlice);
            assertMessage("Iteration: " + i + ", message Alice: " + messageAlice, messageAlice, c.clientBob.receiveMessage().content);
        }
    }

    @Test
    public void testFragmentWithIllegalMetadataMismatchedSenderTag() throws OtrException {
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.restoreClientProfilePayload()).thenReturn(new byte[0]);
        when(host.getSessionPolicy(eq(sessionID))).thenReturn(new OtrPolicy(OTRV4_INTERACTIVE_ONLY));
        final ClientProfileTestUtils utils = new ClientProfileTestUtils();
        final ClientProfilePayload clientProfilePayload = utils.createClientProfile();
        final ClientProfile clientProfile = clientProfilePayload.validate(Instant.now());
        when(host.getLongTermKeyPair(eq(sessionID))).thenReturn(utils.getLongTermKeyPair());
        when(host.getForgingKeyPair(eq(sessionID))).thenReturn(utils.getForgingKeyPair());
        when(host.getLocalKeyPair(eq(sessionID))).thenReturn(utils.getLegacyKeyPair());
        final Session session = createSession(sessionID, host);
        final Point y = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger b = DHKeyPair.generate(RANDOM).publicKey();
        final Point firstECDH = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger firstDH = DHKeyPair.generate(RANDOM).publicKey();
        final String message = writeMessage(new IdentityMessage(new InstanceTag(0xffffffff),
                clientProfile.getInstanceTag(), clientProfilePayload, y, b, firstECDH, firstDH));

        // Using incorrect sender tag.
        final String illegalFragment = "?OTR|00000001|00000100|"
                + Integer.toHexString(clientProfile.getInstanceTag().getValue()) + ",1,1," + message + ",";
        assertNull(session.transformReceiving(illegalFragment).content);
    }

    @Test
    public void testFragmentWithIllegalMetadataMismatchedReceiverTag() throws OtrException {
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.restoreClientProfilePayload()).thenReturn(new byte[0]);
        when(host.getSessionPolicy(eq(sessionID))).thenReturn(new OtrPolicy(OTRV4_INTERACTIVE_ONLY));
        final ClientProfileTestUtils utils = new ClientProfileTestUtils();
        final ClientProfilePayload clientProfilePayload = utils.createClientProfile();
        final ClientProfile clientProfile = clientProfilePayload.validate(Instant.now());
        when(host.getLongTermKeyPair(eq(sessionID))).thenReturn(utils.getLongTermKeyPair());
        when(host.getForgingKeyPair(eq(sessionID))).thenReturn(utils.getForgingKeyPair());
        final Session session = createSession(sessionID, host);
        final Point y = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger b = DHKeyPair.generate(RANDOM).publicKey();
        final Point firstECDH = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger firstDH = DHKeyPair.generate(RANDOM).publicKey();
        final String message = writeMessage(new IdentityMessage(new InstanceTag(256),
                clientProfile.getInstanceTag(), clientProfilePayload, y, b, firstECDH, firstDH));

        // Using incorrect receiver tag.
        final String illegalFragment = "?OTR|00000001|00000100|fffffffe,1,1," + message + ",";
        assertNull(session.transformReceiving(illegalFragment).content);
    }

    @Test
    public void testFragmentWithIllegalMetadataMismatchedProtocolVersion() throws OtrException {
        final SessionID sessionID = new SessionID("bob", "alice", "network");
        final OtrEngineHost host = mock(OtrEngineHost.class);
        when(host.restoreClientProfilePayload()).thenReturn(new byte[0]);
        when(host.getSessionPolicy(eq(sessionID))).thenReturn(new OtrPolicy(OTRV4_INTERACTIVE_ONLY));
        final ClientProfileTestUtils utils = new ClientProfileTestUtils();
        final ClientProfilePayload clientProfilePayload = utils.createClientProfile();
        final ClientProfile clientProfile = clientProfilePayload.validate(Instant.now());
        when(host.getLongTermKeyPair(eq(sessionID))).thenReturn(utils.getLongTermKeyPair());
        when(host.getForgingKeyPair(eq(sessionID))).thenReturn(utils.getForgingKeyPair());
        final Session session = createSession(sessionID, host);
        final Point y = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger b = DHKeyPair.generate(RANDOM).publicKey();
        final Point firstECDH = ECDHKeyPair.generate(RANDOM).publicKey();
        final BigInteger firstDH = DHKeyPair.generate(RANDOM).publicKey();
        final String message = writeMessage(new IdentityMessage(new InstanceTag(256),
                clientProfile.getInstanceTag(), clientProfilePayload, y, b, firstECDH, firstDH));

        // Using OTRv3 protocol format, hence protocol version mismatches with OTRv4 Identity message.
        final String illegalFragment = "?OTR|00000100|" + Integer.toHexString(clientProfile.getInstanceTag().getValue())
                + ",1,1," + message + ",";
        assertNull(session.transformReceiving(illegalFragment).content);
    }

    @Test
    public void testOTR4SmallConversationWithMaliciousDataMessages() throws OtrException, ProtocolException, InterruptedException {
        final Conversation c = new Conversation(1);
        c.clientBob.sendMessage(InstanceTag.ZERO_TAG, "Hi Alice");
        assertEquals("Hi Alice", c.clientAlice.receiveMessage().content);
        // Initiate OTR by sending query message.
        c.clientAlice.session.startSession();
        assertNull(c.clientBob.receiveMessage().content);
        // Expecting Identity message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        // Expecting AUTH_R message from Alice.
        assertNull(c.clientBob.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).getSessionStatus());
        // Expecting AUTH_I message from Bob.
        assertNull(c.clientAlice.receiveMessage().content);
        assertEquals(ENCRYPTED, c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).getSessionStatus());

        final Random random = createDeterministicRandom(RANDOM.nextLong());
        final ECDHKeyPair maliciousECDH = ECDHKeyPair.generate(RANDOM);
        final DHKeyPair maliciousDH = DHKeyPair.generate(RANDOM);
        for (int i = 0; i < 5; i++) {
            System.err.println("Test loop iteration: " + i);
            // Bob sending a message
            final String messageBob = randomMessage(random, 50000);
            c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), messageBob);
            // Inject malicious messages to throw off the DoubleRatchet procedure.
            final String raw = c.clientAlice.receiptChannel.remove();
            final DataMessage4 original = (DataMessage4) EncodedMessageParser.parseEncodedMessage(
                    (EncodedMessage) MessageProcessor.parseMessage(raw));
            // Craft malicious message with same message ID in same ratchet. (and different public keys)
            final DataMessage4 malicious = new DataMessage4(original.senderTag, original.receiverTag,
                    (byte) 0, random.nextInt(15), original.i, original.j, maliciousECDH.publicKey(),
                    original.i % 3 == 0 ? maliciousDH.publicKey() : null, randomBytes(RANDOM, new byte[250]),
                    randomBytes(RANDOM, new byte[OtrCryptoEngine4.AUTHENTICATOR_LENGTH_BYTES]), new byte[0]);
            c.clientAlice.receiptChannel.put(writeMessage(malicious));
            assertNull(c.clientAlice.receiveMessage().content);
            assertEquals(0, c.clientBob.receiptChannel.size());
            // Craft malicious message with arbitrary future message in same ratchet. (and different public keys)
            final DataMessage4 malicious2 = new DataMessage4(original.senderTag, original.receiverTag,
                    (byte) 0, random.nextInt(50), original.i, original.j + random.nextInt(100),
                    maliciousECDH.publicKey(), original.i % 3 == 0 ? maliciousDH.publicKey() : null,
                    randomBytes(RANDOM, new byte[250]), randomBytes(RANDOM, new byte[OtrCryptoEngine4.AUTHENTICATOR_LENGTH_BYTES]),
                    new byte[0]);
            c.clientAlice.receiptChannel.put(writeMessage(malicious2));
            assertNull(c.clientAlice.receiveMessage().content);
            assertEquals(0, c.clientBob.receiptChannel.size());
            // (Re)inject original message.
            c.clientAlice.receiptChannel.put(raw);
            assertMessage("Iteration: " + i + ", message Bob.", messageBob, c.clientAlice.receiveMessage().content);

            // Bob sending another message
            final String messageBob2 = randomMessage(random, 50000);
            c.clientBob.sendMessage(c.clientAlice.session.getSenderInstanceTag(), messageBob2);
            // Inject malicious messages to throw off the DoubleRatchet procedure.
            final String raw2 = c.clientAlice.receiptChannel.remove();
            final DataMessage4 original2 = (DataMessage4) EncodedMessageParser.parseEncodedMessage(
                    (EncodedMessage) MessageProcessor.parseMessage(raw2));
            // Craft malicious message as first message in next ratchet. (and different public keys)
            final int nextI = original2.i + 1;
            final DataMessage4 malicious3 = new DataMessage4(original2.senderTag, original2.receiverTag,
                    (byte) 0, random.nextInt(10), nextI, 0, maliciousECDH.publicKey(),
                    nextI % 3 == 0 ? maliciousDH.publicKey() : null, randomBytes(RANDOM, new byte[250]),
                    randomBytes(RANDOM, new byte[OtrCryptoEngine4.AUTHENTICATOR_LENGTH_BYTES]), new byte[0]);
            c.clientAlice.receiptChannel.put(writeMessage(malicious3));
            assertNull(c.clientAlice.receiveMessage().content);
            // Craft malicious message as first message in (impossible) future ratchet. (and different public keys)
            final int futureI = original2.i + 2 + random.nextInt(10);
            final DataMessage4 malicious4 = new DataMessage4(original2.senderTag, original2.receiverTag,
                    (byte) 0, random.nextInt(10), futureI, 0, maliciousECDH.publicKey(),
                    futureI % 3 == 0 ? maliciousDH.publicKey() : null, randomBytes(RANDOM, new byte[250]),
                    randomBytes(RANDOM, new byte[OtrCryptoEngine4.AUTHENTICATOR_LENGTH_BYTES]), new byte[0]);
            c.clientAlice.receiptChannel.put(writeMessage(malicious4));
            assertNull(c.clientAlice.receiveMessage().content);
            // (Re)inject original message.
            c.clientAlice.receiptChannel.put(raw2);
            assertMessage("Iteration: " + i + ", message Bob.", messageBob2, c.clientAlice.receiveMessage().content);

            // Alice sending a message (alternating, to enable ratchet)
            final String messageAlice = randomMessage(random, 1000000);
            c.clientAlice.sendMessage(c.clientBob.session.getSenderInstanceTag(), messageAlice);
            assertMessage("Iteration: " + i + ", message Alice.", messageAlice, c.clientBob.receiveMessage().content);
        }
        c.clientAlice.session.getInstance(c.clientBob.session.getSenderInstanceTag()).endSession();
        c.clientBob.session.getInstance(c.clientAlice.session.getSenderInstanceTag()).endSession();
    }

    private static void assertMessage(final String message, final String expected, final String actual) {
        if (expected.length() == 0) {
            assertNull(message, actual);
        } else {
            assertEquals(message, expected, actual);
        }
    }

    private static String randomMessage(final Random random, final int maxLength) {
        // NOTE: cannot use length 0, because that would give `null` content, instead of zero-length content.
        return randomMessage(random, 1, maxLength);
    }

    @SuppressWarnings("SameParameterValue")
    private static String randomMessage(final Random random, final int minLength, final int maxLength) {
        final byte[] arbitraryContent = new byte[minLength + random.nextInt(maxLength - minLength)];
        random.nextBytes(arbitraryContent);
        return toBase64String(arbitraryContent);
    }

    private static Random createDeterministicRandom(final long seed) {
        LOGGER.info("Random seed: " + seed);
        return new Random(seed);
    }

    /**
     * Dummy conversation implementation, mimicking a conversation between two parties.
     */
    private static final class Conversation {

        private final SessionID sessionIDAlice;
        private final SessionID sessionIDBob;

        private final Client clientAlice;
        private final Client clientBob;

        private final BlockingSubmitter<String> submitterBob;
        private final BlockingSubmitter<String> submitterAlice;

        /**
         * Constructor with defaults: Unlimited-length messages.
         */
        private Conversation(final int channelCapacity) {
            final LinkedBlockingQueue<String> directChannelAlice = new LinkedBlockingQueue<>(channelCapacity);
            submitterAlice = new BlockingSubmitter<>();
            submitterAlice.addQueue(directChannelAlice);
            final LinkedBlockingQueue<String> directChannelBob = new LinkedBlockingQueue<>(channelCapacity);
            submitterBob = new BlockingSubmitter<>();
            submitterBob.addQueue(directChannelBob);
            this.sessionIDBob = new SessionID("bob@InMemoryNetwork4", "alice@InMemoryNetwork4",
                    "InMemoryNetwork4");
            this.sessionIDAlice = new SessionID("alice@InMemoryNetwork4", "bob@InMemoryNetwork4",
                    "InMemoryNetwork4");
            this.clientBob = new Client("Bob", sessionIDBob, new OtrPolicy(OTRL_POLICY_MANUAL), submitterAlice,
                    directChannelBob);
            this.clientAlice = new Client("Alice", sessionIDAlice, new OtrPolicy(OTRL_POLICY_MANUAL), submitterBob,
                    directChannelAlice);
        }

        private Conversation(final int channelCapacity, final int maxMessageSize) {
            this(channelCapacity, maxMessageSize, new OtrPolicy(OTRL_POLICY_MANUAL));
        }

        /**
         * Constructor with configurable maximum message size and channel capacity (maximum number of messages
         * simultaneously stored).
         *
         * @param maxMessageSize  Maximum size of message allowed.
         * @param channelCapacity Maximum number of messages allowed to be in transit simultaneously.
         */
        private Conversation(final int channelCapacity, final int maxMessageSize, final OtrPolicy policy) {
            final Predicate<String> condition = new MaxMessageSize(maxMessageSize);
            final ConditionalBlockingQueue<String> directChannelAlice = new ConditionalBlockingQueue<>(condition,
                    new LinkedBlockingQueue<>(channelCapacity));
            submitterAlice = new BlockingSubmitter<>();
            submitterAlice.addQueue(directChannelAlice);
            final ConditionalBlockingQueue<String> directChannelBob = new ConditionalBlockingQueue<>(condition,
                    new LinkedBlockingQueue<>(channelCapacity));
            submitterBob = new BlockingSubmitter<>();
            submitterBob.addQueue(directChannelBob);
            this.sessionIDBob = new SessionID("bob@InMemoryNetwork4", "alice@InMemoryNetwork4",
                    "InMemoryNetwork4");
            this.sessionIDAlice = new SessionID("alice@InMemoryNetwork4", "bob@InMemoryNetwork4",
                    "InMemoryNetwork4");
            this.clientBob = new Client("Bob", sessionIDBob, policy, submitterAlice, directChannelBob);
            this.clientBob.setMessageSize(maxMessageSize);
            this.clientAlice = new Client("Alice", sessionIDAlice, policy, submitterBob, directChannelAlice);
            this.clientAlice.setMessageSize(maxMessageSize);
        }
    }

    /**
     * Predicate to verify maximum message size.
     */
    private static final class MaxMessageSize implements Predicate<String> {
        private final int maximum;

        private MaxMessageSize(final int maximum) {
            this.maximum = maximum;
        }

        @Override
        public boolean test(final String s) {
            return s.length() <= maximum;
        }
    }

    /**
     * Dummy client implementation for use with OTRv4 protocol tests.
     */
    @SuppressWarnings({"FieldCanBeLocal", "SameParameterValue"})
    private static final class Client implements OtrEngineHost {

        private final Logger logger;

        private final HashSet<ByteArrays.Bytes> verified = new HashSet<>();

        private final DSAKeyPair dsaKeyPair = generateDSAKeyPair(RANDOM);

        private final EdDSAKeyPair ed448KeyPair = EdDSAKeyPair.generate(RANDOM);

        private final EdDSAKeyPair forgingKeyPair = EdDSAKeyPair.generate(RANDOM);

        private final BlockingSubmitter<String> sendChannel;

        private final BlockingQueue<String> receiptChannel;

        private final Session session;
        
        private byte[] payload = new byte[0];

        private OtrPolicy policy;

        private int messageSize = MAX_VALUE;

        private Client(final String id, final SessionID sessionID, final OtrPolicy policy,
                final BlockingSubmitter<String> sendChannel, final BlockingQueue<String> receiptChannel) {
            this.logger = Logger.getLogger(Client.class.getSimpleName() + ":" + id);
            this.receiptChannel = requireNonNull(receiptChannel);
            this.sendChannel = requireNonNull(sendChannel);
            this.policy = requireNonNull(policy);
            this.session = createSession(sessionID, this);
        }

        void setMessageSize(final int messageSize) {
            this.messageSize = messageSize;
        }

        @Nonnull
        Session.Result receiveMessage() throws OtrException {
            final String msg = this.receiptChannel.remove();
            //logger.warning(msg);
            return this.session.transformReceiving(msg);
        }

        @Nonnull
        String[] receiveAllMessages(@SuppressWarnings("SameParameterValue") final boolean skipNulls) throws OtrException {
            final ArrayList<String> messages = new ArrayList<>();
            this.receiptChannel.drainTo(messages);
            final ArrayList<String> results = new ArrayList<>();
            for (final String msg : messages) {
                final Session.Result result = this.session.transformReceiving(msg);
                if (result.content == null && skipNulls) {
                    continue;
                }
                results.add(result.content);
            }
            return results.toArray(new String[0]);
        }

        void sendMessage(final InstanceTag tag, final String msg) throws OtrException {
            //logger.warning(msg);
            this.sendChannel.addAll(asList(this.session.getInstance(tag).transformSending(msg)));
        }

        void setPolicy(final OtrPolicy policy) {
            this.policy = requireNonNull(policy);
        }

        @Override
        public void injectMessage(final SessionID sessionID, final String msg) {
            this.sendChannel.add(msg);
        }

        @Nonnull
        @Override
        public OtrPolicy getSessionPolicy(final SessionID sessionID) {
            return this.policy;
        }

        @Override
        public int getMaxFragmentSize(final SessionID sessionID) {
            return this.messageSize;
        }

        @Nonnull
        @Override
        public DSAKeyPair getLocalKeyPair(final SessionID sessionID) {
            return this.dsaKeyPair;
        }

        @Nonnull
        @Override
        public EdDSAKeyPair getLongTermKeyPair(final SessionID sessionID) {
            return this.ed448KeyPair;
        }

        @Nonnull
        @Override
        public EdDSAKeyPair getForgingKeyPair(final SessionID sessionID) {
            return this.forgingKeyPair;
        }

        @Nonnull
        @Override
        public byte[] restoreClientProfilePayload() {
            return this.payload;
        }

        @Override
        public void updateClientProfilePayload(final byte[] payload) {
            this.payload = payload;
        }

        @Nonnull
        @Override
        public String getReplyForUnreadableMessage(final SessionID sessionID, final String identifier) {
            return "The message is unreadable. (Session: " + sessionID + ")";
        }

        @Override
        public String getFallbackMessage(final SessionID sessionID) {
            return null;
        }

        @Override
        public <T> void handleEvent(final SessionID sessionID, final InstanceTag receiver,
                final Event<T> event, final T payload) {
            if (event == Event.ENCRYPTED_MESSAGES_REQUIRED) {
                final String msg = Event.ENCRYPTED_MESSAGES_REQUIRED.convert(payload);
                logger.log(FINEST, "Encrypted session is required by policy for {0}). (message: {1})",
                        new Object[]{sessionID, msg});
            } else if (event == Event.UNREADABLE_MESSAGE_RECEIVED) {
                logger.log(FINEST, "Unreadable message received. (Session: {0})", new Object[]{sessionID});
            } else if (event == Event.UNENCRYPTED_MESSAGE_RECEIVED) {
                final String msg = Event.UNENCRYPTED_MESSAGE_RECEIVED.convert(payload);
                logger.log(FINEST, "Message received unencrypted: {1} (Session: {0})", new Object[]{sessionID, msg});
            } else if (event == Event.ERROR) {
                final String error = Event.ERROR.convert(payload);
                logger.log(FINEST, "Error for session: {0}: {1}", new Object[]{sessionID, error});
            } else if (event == Event.SESSION_FINISHED) {
                logger.log(FINEST, "Encrypted session finished for {1}. (Session: {0})",
                        new Object[]{sessionID, receiver});
            } else if (event == Event.EXTRA_SYMMETRIC_KEY_DISCOVERED) {
                // TODO take payload
                logger.log(FINEST, "Extra symmetric key TLV discovered in encoded message. (Session: {0})",
                        new Object[]{sessionID});
            } else if (event == Event.MESSAGE_FOR_ANOTHER_INSTANCE_RECEIVED) {
                logger.log(FINEST, "Message from another instance received: {1} (Session: {0})",
                        new Object[]{sessionID, receiver});
            } else if (event == Event.SMP_ABORTED) {
                logger.log(FINEST, "SMP process is aborted for {1}. (Session: {0})",
                        new Object[]{sessionID, receiver});
            } else if (event == Event.SMP_COMPLETED) {
                final Event.SMPResult result = Event.SMP_COMPLETED.convert(payload);
                logger.finest("(Un)verifying fingerprint " + new String(result.fingerprint, UTF_8) + " (Session: " + sessionID + ")");
                if (result.success) {
                    this.verified.add(new ByteArrays.Bytes(result.fingerprint));
                } else {
                    this.verified.remove(new ByteArrays.Bytes(result.fingerprint));
                }
            } else if (event == Event.SMP_REQUEST_SECRET) {
                final String question = Event.SMP_REQUEST_SECRET.convert(payload);
                logger.log(FINEST, "A request for the secret was received. (Question: " + question + ") [NOT IMPLEMENTED, LOGGING ONLY]");
            } else {
                throw new UnsupportedOperationException("BUG: received unknown EventType:  " + event.getClass().getName());
            }
        }
    }
}
