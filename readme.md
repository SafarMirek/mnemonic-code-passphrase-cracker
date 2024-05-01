# Mnemonic Code Passphrase Cracker

A tool for running a dictionary attack on mnemonic code passphrase. It is a fork of popular tool https://github.com/iancoleman/bip39.

## Online Version

https://mnemonic.safar.dev

## Standalone offline version

Download `mnemonic_attack.html` from
[the releases](https://github.com/safardev/mnemonic-code-passphrase-cracker/releases).

Open the file in a browser by double clicking it.

This can be compiled from source using the command `python compile_attack.py`

## Usage

Enter your BIP39 phrase into the 'BIP39 Mnemonic', select the file with the dictionary, and select the coin.

For most popular coins, there are specified blockbook URLs, if one is not specified, you need to provide the URL of the blockbook instance for the given coin.

### Some important fields

#### Dictionary Format
The dictionary file should be in text format with one word per line. The empty word is automatically added to the list and is always considered the first word in the list.
```text
secretPassword1
secretPassword2
password
```

#### Blockbook
For checking of resources behind the generated addresses, application uses [Blockbook](https://github.com/trezor/blockbook/tree/master). It is important to mention application uses its web socket API to communicate to avoid rate limitations. 

#### Address Gap
The Bitcoin proposal BIP44 specifies the address gap. It is a number of unused addresses from the start after which resource discovery is stopped. BIP44 sets this limit to 20, but not
all wallets enforce that, and in some the gap is configurable. Increasing the gap can lead to the discovery of some resources, but it also increases the time complexity of the search.
It is suggested to use default 20 and use different number only if you have suspicions that a different limit was used.

#### Account Gap
The Bitcoin Proposal BIP44 also specifies that a new account can only be created if the previous one is used, but this is
also broken by some wallets, for example, the Electrum wallet does allow users to specify any account number.
If you have suspicions user tried to hide the assets by using some bigger number as the account number, increase the gap accordingly, or if you discover the unusual derivation path, you can use the BIP141 options and specify the derivation path by yourself.

## Making changes

Please do not make modifications to `mnemonic_attack.html`, since they will
be overwritten by `compile_attack.py`.

Make changes in `src/*`.

Changes are applied during release using the command `python compile_attack.py`, so
please do not commit changes to `mnemonic_attack.html`

# License

This BIP39 tool is released under the terms of the MIT license. See LICENSE for
more information or see https://opensource.org/licenses/MIT.
