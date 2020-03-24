cmake_minimum_required(VERSION 3.15)
project(AES)

set(CMAKE_CXX_STANDARD 14)

add_executable(AES main.cpp AES128_Constants.h)