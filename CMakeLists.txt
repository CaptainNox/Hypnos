cmake_minimum_required(VERSION 3.25)
project(Hypnos C)

set(CMAKE_C_STANDARD 11)

add_executable(Hypnos main.c src/hypnos.h example/main.c src/hypnos.c src/hypnos.c util/hash.c src/hypnos.c)
