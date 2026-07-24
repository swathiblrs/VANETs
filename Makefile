CXX ?= c++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -pedantic

.PHONY: all run experiment clean

all: build/vanet_sim build/vanet_experiment

build/vanet_sim: vanet_sim.cpp
	mkdir -p build
	$(CXX) $(CXXFLAGS) $< -o $@

run: build/vanet_sim
	./build/vanet_sim

build/vanet_experiment: vanet_experiment.cpp
	mkdir -p build
	$(CXX) $(CXXFLAGS) $< -o $@

experiment: build/vanet_experiment
	./build/vanet_experiment

clean:
	rm -rf build
