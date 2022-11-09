# nf-injector

## Description
nf-injector controller

## Usage

### Fetch the package
`kpt pkg get REPO_URI[.git]/PKG_PATH[@VERSION] nf-injector`
Details: https://kpt.dev/reference/cli/pkg/get/

### View package content
`kpt pkg tree nf-injector`
Details: https://kpt.dev/reference/cli/pkg/tree/

### Apply the package
```
kpt live init nf-injector
kpt live apply nf-injector --reconcile-timeout=2m --output=table
```
Details: https://kpt.dev/reference/cli/live/
