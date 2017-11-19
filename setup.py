from setuptools import setup, find_packages

setup(name='token',
      version='0.0.1',
      description='Universal Token API for generating and validating time limited access tokens.',
      url='https://github.com/mpavelka/python-token',
      author='Miloslav Pavelka',
      author_email='pavelkamiloslav@gmail.com',
      license='BSD-3',
      packages=find_packages(),
      zip_safe=False)
