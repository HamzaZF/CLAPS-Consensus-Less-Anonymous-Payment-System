# CLAPS-ZKP-Implementation

This project implements a Zero-Knowledge Proof (ZKP) related to the paper titled "CLAPS: Consensus-Less Anonymous Payment System". This ZKP has been implemented using gnark, a fast zk-SNARK library that offers a high-level API to design circuits.

## Table of Contents
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)
- [Contact](#contact)

## Installing gnark

To install gnark, you need to have Go installed on your machine. Follow these steps to set up gnark:

1. Open a terminal on your machine.
2. Install Go if you haven't already. You can download it from [here](https://golang.org/dl/).

3. Set up your Go workspace by adding the following lines to your shell profile (`~/.bashrc`, `~/.zshrc`, etc.):

    ```bash
    export GOPATH=$HOME/go
    export PATH=$PATH:$GOPATH/bin
    ```

4. Source your shell profile to apply the changes:

    ```bash
    source ~/.bashrc  # or source ~/.zshrc
    ```

5. Install gnark by running:

    ```bash
    go get github.com/ConsenSys/gnark
    ```

## Usage

To execute a ZKP using gnark, follow these steps:

1. Navigate to the directory containing your gnark project.
2. Compile, prove and verify the circuit:

    ```bash
    go run main.go
    ```

These commands will trigger the compilation, proving, and verification processes at the same time (see main.go for the implementation details of these processes).

## License

This project is licensed under the MIT License - see the LICENSE.md file for details.

## Contact

If you have any questions or suggestions regarding this implementation, feel free to reach out to me at [hamza.zarfaoui@telecom-paris.fr].
