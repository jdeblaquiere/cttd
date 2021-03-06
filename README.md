# cttd

cttd is the ciphrtxt token coin node implementation. It is derived from cttd (see cttd information below). In addition to having unique network identifiers cttd changes the POW algorithm and extends the bitcoin protocol by creating two additional script opcodes to support the ciphrtxt network. The extension script opcodes are:

1. OP_REGISTERACCESSKEY (OP_NOP5) - used to register a 101-byte access key which includes the information below. In order for the NAK to be considered valid by the msgstore service it must return a fee to the miner (coinbase transaction)
 * (04 bytes) unsigned integer unix time for expiration of key
 * (33 bytes) compressed ECC public key (EC point)
 * (64 bytes) ecdsa signature (r,s) for the time and key

2. OP_POSTDIRECTORY (OP_NOP7) - used to post a directory object (documentation pending)

cttd
====

[![Build Status](https://travis-ci.org/btcsuite/cttd.png?branch=master)]
(https://travis-ci.org/btcsuite/cttd)

cttd is an alternative full node bitcoin implementation written in Go (golang).

This project is currently under active development and is in a Beta state.  It
is extremely stable and has been in production use since October 2013.

It properly downloads, validates, and serves the block chain using the exact
rules (including bugs) for block acceptance as Bitcoin Core.  We have taken
great care to avoid cttd causing a fork to the block chain.  It passes all of
the 'official' block acceptance tests
(https://github.com/TheBlueMatt/test-scripts) as well as all of the JSON test
data in the Bitcoin Core code.

It also relays newly mined blocks, maintains a transaction pool, and relays
individual transactions that have not yet made it into a block.  It ensures all
transactions admitted to the pool follow the rules required by the block chain
and also includes the same checks which filter transactions based on
miner requirements ("standard" transactions) as Bitcoin Core.

One key difference between cttd and Bitcoin Core is that cttd does *NOT* include
wallet functionality and this was a very intentional design decision.  See the
blog entry [here](https://blog.conformal.com/cttd-not-your-moms-bitcoin-daemon)
for more details.  This means you can't actually make or receive payments
directly with cttd.  That functionality is provided by the
[cttwallet](https://github.com/btcsuite/cttwallet) and
[Paymetheus](https://github.com/btcsuite/Paymetheus) (Windows-only) projects
which are both under active development.

## Requirements

[Go](http://golang.org) 1.6 or newer.

## Installation

#### Linux/BSD/MacOSX/POSIX - Build from Source

- Install Go according to the installation instructions here:
  http://golang.org/doc/install

- Ensure Go was installed properly and is a supported version:

```bash
$ go version
$ go env GOROOT GOPATH
```

NOTE: The `GOROOT` and `GOPATH` above must not be the same path.  It is
recommended that `GOPATH` is set to a directory in your home directory such as
`~/goprojects` to avoid write permission issues.  It is also recommended to add
`$GOPATH/bin` to your `PATH` at this point.

- Run the following commands to obtain cttd, all dependencies, and install it:

```bash
$ go get -u github.com/Masterminds/glide
$ git clone https://github.com/jadeblaquiere/cttd $GOPATH/src/github.com/jadeblaquiere/cttd
$ cd $GOPATH/src/github.com/jadeblaquiere/cttd
$ glide install
$ go install . ./cmd/...
```

- cttd (and utilities) will now be installed in ```$GOPATH/bin```.  If you did
  not already add the bin directory to your system path during Go installation,
  we recommend you do so now.

## Updating

#### Windows

Install a newer MSI

#### Linux/BSD/MacOSX/POSIX - Build from Source

- Run the following commands to update cttd, all dependencies, and install it:

```bash
$ cd $GOPATH/src/github.com/jadeblaquiere/cttd
$ git pull && glide install
$ go install . ./cmd/...
```

## Getting Started

cttd has several configuration options avilable to tweak how it runs, but all
of the basic operations described in the intro section work with zero
configuration.

#### Windows (Installed from MSI)

Launch cttd from your Start menu.

#### Linux/BSD/POSIX/Source

```bash
$ ./cttd
````

## IRC

- irc.freenode.net
- channel #cttd
- [webchat](https://webchat.freenode.net/?channels=cttd)

## Mailing lists

- cttd: discussion of cttd and its packages.
- cttd-commits: readonly mail-out of source code changes.

To subscribe to a given list, send email to list+subscribe@opensource.conformal.com

## Issue Tracker

The [integrated github issue tracker](https://github.com/jadeblaquiere/cttd/issues)
is used for this project.

## Documentation

The documentation is a work-in-progress.  It is located in the [docs](https://github.com/jadeblaquiere/cttd/tree/master/docs) folder.

## GPG Verification Key

All official release tags are signed by Conformal so users can ensure the code
has not been tampered with and is coming from the btcsuite developers.  To
verify the signature perform the following:

- Download the public key from the Conformal website at
  https://opensource.conformal.com/GIT-GPG-KEY-conformal.txt

- Import the public key into your GPG keyring:
  ```bash
  gpg --import GIT-GPG-KEY-conformal.txt
  ```

- Verify the release tag with the following command where `TAG_NAME` is a
  placeholder for the specific tag:
  ```bash
  git tag -v TAG_NAME
  ```

## License

cttd is licensed under the [copyfree](http://copyfree.org) ISC License.
