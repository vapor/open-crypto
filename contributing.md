# Contribution Notes

Thanks for contributing! Here are some notes to help development.

## macOS

On macOS, you can install different OpenSSL versions using Homebrew.

```sh
brew install openssl@1.0
brew install openssl@1.1
```

From there, you can choose which version you use by running the following command:

```sh
export PKG_CONFIG_PATH="/usr/local/opt/openssl@1.0/lib/pkgconfig"
```

After running that `export` command, if you clean and re-generate Xcode, you will be linked against the OpenSSL version you chose.

## Linux

Use the included Docker files to test on Ubuntu. Using Docker compose makes this easy.

```sh
docker-compose up --build test
```

