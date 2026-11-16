# Release checklist

biscuit-swift is part of the [Eclipse Biscuit](https://projects.eclipse.org/projects/technology.biscuit) project and as such needs to conform the eclipse project management guidelines.

Eclipse projects can only be released within the validity period of a release review (they last for 1 year).

## Pre-release

- make sure `README.md`, `CODE_OF_CONDUCT.md`, `SECURITY.md` are present and up-to-date
- make sure `LICENSE-APACHE` is present and that all source files are properly annotated with copyright and license information
- make sure dependency license information is correctly vetted:

```bash
swift package resolve
jq -r '.pins[] | (.location | sub("^https://github.com/"; "git/github/") | sub("\\.git$"; "")) + "/" + .state.revision' Package.resolved | java -jar org.eclipse.dash.licenses-1.1.0.jar -
```
(you’ll need to download the [eclipse dash licenses jar](repo.eclipse.org/content/repositories/dash-licenses/org/eclipse/dash/org.eclipse.dash.licenses/))

This check runs in CI, in the `licenses` job of `.github/workflows/swift.yml`.

## Requesting a release review

If the most recent release review is outdated, we will need to start a new one on the [project governance page](https://projects.eclipse.org/projects/technology.biscuit/governance).

## Actually releasing stuff

Swift packages are distributed directly from the git repository, so a release is just a git tag.

- update `CHANGELOG.md` (ideally, try to update it in each PR, in an _unreleased_ section to make things easier);
- merge the PR;
- tag the new `main` commit with the version number, without prefix (eg `x.y.z`, not `vx.y.z`), and push the tag.
