# -*- coding: utf-8 -*-
"""
Created on Tue Dec 12 00:35:33 2023

@author: DELL 3550
"""

from cx_Freeze import setup, Executable

setup(
    name="OpenSSL Security Toolkit",
    version="1.0",
    description="Your application description",
    executables=[Executable("GUI.py", base="Win32GUI")],
)
