# A Generic IoT Quantum-Safe Watchdog Timer Protocol

This repository contains the proof-of-concept (PoC) implementation for the ARES 2023 paper "A Generic IoT Quantum-Safe Watchdog Timer Protocol" by [Michael Eckel](https://github.com/eckelmeckel), [Tanja Gutsche](https://github.com/Tanja839), [Hagen Lauer](https://github.com/hagenlauer), and [André Rein](https://github.com/xrayn).
It appeared in The 18th International Conference on Availability, Reliability and Security (ARES 2023), August 29-September 1, 2023, Benevento, Italy.
ACM, New York, NY, USA, 10 pages.
<https://doi.org/10.1145/3600160.3605169>

Tanja Gutsche developed this renewed protocol as part of her master's thesis at the [Technical University of Applied Sciences Mittelhessen (THM)](https://www.thm.de/) in collaboration with [Fraunhofer SIT](https://www.sit.fraunhofer.de/).
It is a pure proof-of-concept implementation in software and comes with no warranty or any liabilities (refer to the [`LICENSE` file](./LICENSE.md) for details).

## Running with Docker

The following assumes that [Docker](https://docs.docker.com/get-docker/) (and [Docker Compose](https://docs.docker.com/compose/install/)) are installed and configured on your system.
All commands are to be executed in [Bash](https://www.gnu.org/software/bash/).

With Docker, build the image and run the container with:

```bash
./docker/build.sh
./docker/run.sh
```

With Docker Compose do:

```bash
docker-compose build --build-arg uid="${UID}" --build-arg gid="${UID}"
docker-compose run --rm paper-poc-generic-iot-pq-wdtp
```

## Performing CPU Cycle Measurements

First, think of an algorithm with which you want to perform the CPU cycle measurements, then execute the desired measurement script with the desired parameters (including the algorithm) to perform the measurements.

Enable the Python virtual environment and go to the `benchmarking` folder:

```bash
cd Proof-of-Concept
source .venv/bin/activate
cd benchmarking
```

### liboqs

To measure the CPU cycles of *liboqs* functions, the following can be executed:

```bash
python3 liboqs_functions_measurements.py --number=100 --variant=Falcon-512
```

Available algorithms are (cf. [`liboqs_functions_measurements.py`](Proof-of-Concept/benchmarking/liboqs_functions_measurements.py)):

* Dilithium: `Dilithium3`, `Dilithium5`
* Falcon: `Falcon-512`, `Falcon-1024`
* SPHINCS+ SHA-256: `SPHINCS+-SHA256-128f-robust`, `SPHINCS+-SHA256-128f-simple`, `SPHINCS+-SHA256-128s-robust`, `SPHINCS+-SHA256-128s-simple`, `SPHINCS+-SHA256-192f-robust`, `SPHINCS+-SHA256-192f-simple`, `SPHINCS+-SHA256-192s-robust`, `SPHINCS+-SHA256-192s-simple`, `SPHINCS+-SHA256-256f-robust`, `SPHINCS+-SHA256-256f-simple`, `SPHINCS+-SHA256-256s-robust`, `SPHINCS+-SHA256-256s-simple`
* SPHINCS+ SHAKE-256: `SPHINCS+-SHAKE256-128f-robust`, `SPHINCS+-SHAKE256-128f-simple`, `SPHINCS+-SHAKE256-128s-robust`, `SPHINCS+-SHAKE256-128s-simple`, `SPHINCS+-SHAKE256-192f-robust`, `SPHINCS+-SHAKE256-192f-simple`, `SPHINCS+-SHAKE256-192s-robust`, `SPHINCS+-SHAKE256-192s-simple`, `SPHINCS+-SHAKE256-256f-robust`, `SPHINCS+-SHAKE256-256f-simple`, `SPHINCS+-SHAKE256-256s-robust`, `SPHINCS+-SHAKE256-256s-simple`

### mbed TLS

To measure the CPU cycles of *mbedtls* functions, the following can be executed:

```bash
python3 mbedtls_functions_measurements.py --number=100 --variant=secp256r1
```

Available algorithms are (cf. [`mbedtls_functions_measurements.py`](Proof-of-Concept/benchmarking/mbedtls_functions_measurements.py)):

* secp256r1
* rsa2048
* rsa4096

### Scenarios

To measure the CPU cycles of a specific protocol scenario execute:

```bash
cd ..
```

Then, the following can be executed:

```bash
python3 measurements_scenarios.py --number=100 --crypto=pqc --variant=Falcon-512 --scenario=1
```

```bash
python3 measurements_scenarios.py --number=100 --crypto=pqc --variant=Falcon-512 --scenario=2
```

```bash
python3 measurements_scenarios.py --number=100 --crypto=pqc --variant=Falcon-512 --scenario=3
```

```bash
python3 measurements_scenarios.py --number=100 --crypto=pqc --variant=Falcon-512 --scenario=4
```

```bash
python3 measurements_scenarios.py --number=100 --crypto=pqc --variant=Falcon-512 --scenario=5
```

```bash
python3 measurements_scenarios.py --number=100 --crypto=pqc --variant=Falcon-512 --scenario=6
```

```bash
python3 measurements_scenarios.py --number=100 --crypto=pqc --variant=Falcon-512 --scenario=7
```

```bash
python3 measurements_scenarios.py --number=100 --crypto=pqc --variant=Falcon-512 --scenario=8
```

Finally, deactivate the Python virtual environment and switch back to the main PoC directory:

```bash
deactivate
cd ..
```

There are 8 different scenarios, 6 of which can be measured.

## Regular Execution

If you want to run the Watchdog Timer without any measurements or scenarios start with:

```bash
cd ./Proof-of-Concept
source .venv/bin/activate
```

Then, the keys need to be generated:

```bash
python3 key_generation.py --crypto=pqc --variant=Falcon-1024
```

Lastly, run the application:
> You can choose between the algorithms mentioned above

```bash
python3 app.py --crypto=pqc --variant=Falcon-1024
```

The internal state of the Watchdog Timer changes after a single execution and shutdown.
To restart the Watchdog Timer, run the above-mentioned command again.
Due to the changed status of the Watchdog Timer, a different pattern of execution will be followed (see [Scenarios](#scenarios))
To regain the original state, measurement files need to be deleted.
Affected files are described in the file [measurements_scenarios.py](Proof-of-Concept/measurements_scenarios.py)

Finally, deactivate the Python virtual environment and switch back to the main PoC directory:

```bash
deactivate
cd ..
```

## Evaluating Results

The evaluation scripts are independent of the proof-of-concept implementation and the measurement scripts.

Therefore, in the `Evaluation` folder, a new virtual environment must be created in which the evaluation scripts can be executed.

```bash
cd Evaluation
source .venv/bin/activate
```

### Placement of Measurement Files

The `.csv` files of the measurement series are stored in the folders `benchmarking/functions` or `benchmarking/scenarios` and must be copied to the `Evaluation/functions` or `Evaluation/scenarios` folder in the respective NIST level or scenario folders and can then be executed therein. This will create evaluation files in `.csv` format.

Functions: classic, NIST_Level_1, NIST_Level_3, NIST_Level_5, Signer_Details
Scenarios: classic, NIST_Level_1, NIST_Level_3, NIST_Level_5 and underneath in one of the  Scenarios: 1, 2, 3, 6, 7, 8

> Please note scenario 4 and 5 are not measureable, as they have randomness in the execution order.

This call tries to copy most files automatically to their correct location.

```bash
python3 ./copy_measurements.py
```

### Execution of the evaluation

The evaluation of the functions is performed through:

```bash
python3 evaluation_functions.py
```

The evaluation of the scenarios is performed through:

```bash
python3 evaluation_scenarios.py
```

The evaluations are located next to the measurements with the naming `evaluation_*.csv`.
