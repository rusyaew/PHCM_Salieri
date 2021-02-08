from setuptools import setup
setup(name='PHCMlib',
      version='0.1',
      description='Part of PHCM backend functionality',
      url='https://gleb.tk/',
      author='Gleb Rusyaev',
      author_email='gleb@gleb.tk',
      license='MIT',
      packages=['PHCMlib'],
      zip_safe=False,
      install_requires=["pycryptodome"],
      classifiers=[
         "Programming Language :: Python :: 3",
         "License :: OSI Approved :: MIT License",
         "Operating System :: OS Independent",
     ])
