# PHCM_Salieri
![](https://img.shields.io/pypi/l/PHCMlib) ![](https://img.shields.io/pypi/pyversions/PHCMlib)
Pseudo-Homomorpic Computational Module based on black-box approach and complexity of hardware reverse-engineering.

In order to test PHCM on the model and server, you may download /demo. It is directory packed with randomly generated key pairs.

Also, the library PHCMlib (https://pypi.org/project/PHCMlib) is on the PyPi.

Instuction how to use demo:
1. install dependencies `(pip3 install -r requirments.txt)`
2. launch server `python3 server/server.py`
3. launch client `python3 client_HSL/client.py`

How to regenerate keys? `python3 kickstart.py`
How to randomise gamma_key? `Erase 8th code line in client_HSL/client.py`
How to change containers? `Head to server/containers. Metadata represents <firmware>\x00<max_input_len>`

