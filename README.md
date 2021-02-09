# PHCM_Salieri
![](https://img.shields.io/pypi/l/PHCMlib) ![](https://img.shields.io/pypi/pyversions/PHCMlib)
Pseudo-Homomorpic Computational Module based on black-box approach and complexity of hardware reverse-engineering.

In order to test PHCM on the model and server, you may download /demo. It is directory packed with randomly generated key pairs.

Also, the library PHCMlib (https://pypi.org/project/PHCMlib) is on the PyPi.

Instuction how to use demo:
 - install dependencies `(pip3 install -r requirments.txt)`
 - launch server `python3 server/server.py`
 -  launch client `python3 client_HSL/client.py`

How to regenerate keys? `python3 kickstart.py`
How to randomise gamma_key? `Erase 8th code line in client_HSL/client.py`
How to change containers? `Head to server/containers. Metadata represents <firmware>\x00<max_input_len>`

Licensing explained:
  - PHCMlib and client under MIT (since it can be used in closed sourse)
  - Server under GNU GPL v3 (there is no need in close-soursing it, since it is yours)
  - Article under GNU GPL v3
 
