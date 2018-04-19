from distutils.core import setup, Extension

module1 = Extension('pySM4', sources=['pySM4.c', 'sm4.c'])
setup(name='pySM4',
      version='1.0',
      description='This is a spam package',
      ext_modules=[module1])
