## Synopsis

otr4j is an implementation of the [OTR (Off The Record) protocol][1]
in java. Its development started during the GSoC '09
where the goal was to add support for OTR in [jitsi][2]. It currently
supports OTRv1, [OTRv2][] and [OTRv3][]. Additionally, there is support
for fragmenting outgoing messages.

For a quick introduction on how to use the library have a look at the
[DummyClient](src/test/java/net/java/otr4j/test/dummyclient/DummyClient.java).

## Contributing

This is the friendly, community fork of jitsi/otr4j that meant to be steered
by contributors.  It also does not require the signing of a Contributor
License Agreement (CLA).

Here are the guidelines everyone follows:

* any developer can request push access, regardless of project or organization affiliation
* _all_ contributors submit code via pull requests
* new commits must be pushed by the reviewer of the pull request, not the author
* "lazy consensus" approach for granting push access:
  * anyone with push access can vote/veto
  * if about a week or so as passed after requesting push access and no one has objected, then that requester can be granted push access

### Git setup

Git makes this kind of workflow easy.  The core idea is to set up each
contributor's git repo as a `git remote`, then you can get all updates using
`git fetch --all`.  You can then view all of the remotes using a good git
history viewer, like `gitk`, which is part of the official git.

For more info: [A tag-team git workflow that incorporates auditing][TagTeamGit]

## Code Style

otr4j uses a code style comparable to the [Android code style
guidelines][AndroidStyle]. The one major exception is that no prefixes for
members and static variables are used. In order to verify that this style and
several additional requirements are met, [Checkstyle] and [PMD] are integrated
into the maven build. As a contributor, please check that your changes adhere
to the style by running `mvn site` and observing the generated HTML outputs at
the location `target/site/index.html`. All major IDEs have plugins to support
inline checks with [Checkstyle] and [PMD], which makes it much easier to verify
the rules already while coding. The respective configuration files can be found
in the `codecheck` folder.

## IDE Integration

### Eclipse

An [Eclipse] project is included with the project. This project is configured
to adhere to the code style of the project. In order to used the project,
install a recent version of [Eclipse] and inside [Eclipse], install the
following plugins:
* [M2Eclipse]: Eclipse maven integration
* [eclipse-cs]: The Eclipse Checkstyle Plugin to get live [Checkstyle] feedback
* [pmd-eclipse]: [PMD] for Eclipse 4 give live PMD reporting
* optionally [EGit]: Eclipse GIT integration

After configuring [Eclipse] appropriately and cloning this repository, open
[Eclipse] and perform these steps:

1. _File -> Import... -> General -> Existing Projects into Workspace_
1. Select the cloned otr4j folder as the _root directory_
1. Ensure that otr4j is selected in the _Projects_ list
1. Click _Finish_

  [1]: https://otr.cypherpunks.ca/
  [2]: https://jitsi.org/
  [OTRv2]: https://otr.cypherpunks.ca/Protocol-v2-3.1.0.html
  [OTRv3]: https://otr.cypherpunks.ca/Protocol-v3-4.0.0.html
  [TagTeamGit]: https://guardianproject.info/2013/11/21/a-tag-team-git-workflow-that-incorporates-auditing/
  [AndroidStyle]: https://source.android.com/source/code-style.html
  [Checkstyle]: http://checkstyle.sourceforge.net/
  [PMD]: http://pmd.sourceforge.net/
  [Eclipse]: http://eclipse.org/
  [M2Eclipse]: https://www.eclipse.org/m2e/
  [eclipse-cs]: http://eclipse-cs.sourceforge.net/
  [pmd-eclipse]: http://pmd.sourceforge.net/eclipse/
  [EGit]: https://www.eclipse.org/egit/
