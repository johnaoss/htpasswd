# htpasswd

htpasswd provides Go-specific implementation of Apache's original htpasswd utility. This includes an optimized version of the Apache-specific APR1 hashing algorithm, which can be used completely separately from the rest of the project.

This project was originally started due to [ingress-nginx](https://github.com/kubernetes/ingress-nginx) requiring users to create their own .htpasswd file by hand, and then manually adding it as a secret. I wanted a nice Terraform deployment in which I wouldn't have to manually run that, but instead would be able to generate / parse those files programatically, in Go.

This project does not have a stable release, however the subpackage `apr1` is considered stable and tested, and unlikely to change.

## Install

For using this package's subpackages, use the following.

```bash
go get -u github.com/johnaoss/htpasswd
```

For CLI usage, please use the following.

```bash
go get -u github.com/johnaoss/htpasswd
go install github.com/johnaoss/htpasswd
```

## Usage

Currently only the flag combination `-nb` is supported, as such you can do the following:

```bash
# Example usage
$ htpasswd -nb user pass
# Example output:
user:$apr1$8Zh7TbIu$K0ksWxmHnnEP5oBLe/y0.0

```

## Planned Features

This is planned to support all functionality that the original `htpasswd` utility does, including parsing and editing the actual .htpasswd files.

Currently only the additional hashing algorithm is introduced, pending my decision on how to properly strucutre this application.

## License

This project is MIT Licensed, with more information available in the proper LICENSE.md file.