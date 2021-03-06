AFL_CXX ?= afl-g++
CXX ?= g++
CPPFLAGS ?= -isystem $(HOME)/git/GSL/include -I..
CXXFLAGS ?= -Wall -Wextra -Werror -Wno-missing-field-initializers -std=c++17 -O3 -ggdb3 -fstack-protector-strong -fsanitize=address,undefined

BIN = parse-test parse-test-afl request-test
parse_test_SRC = parse-test.cpp parser.cpp dns.cpp
request_test_SRC = request-test.cpp serializer.cpp dns.cpp
DEP = $(parse_test_SRC:.cpp=.d) $(request_test_SRC:.cpp=.d)
OBJ = $(parse_test_SRC:.cpp=.o) $(parse_test_SRC:.cpp=.afl.o) $(request_test_SRC:.cpp=.o)
TEST_CASES_BIN = $(patsubst test-cases/%.bm,test-cases-bin/%.bin,$(wildcard test-cases/*.bm))

all: $(BIN) $(TEST_CASES_BIN)

clean:
	$(RM) $(DEP) $(OBJ) $(BIN) $(TEST_CASES_BIN)

%.o: %.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) -MD -MT $@ -MF $(@:.o=.d) -o $@ -c $<

%.afl.o: %.cpp
	AFL_HARDEN=1 $(AFL_CXX) $(CPPFLAGS) $(CXXFLAGS) -MD -MT $@ -MF $(@:.afl.o=.d) -o $@ -c $<

test-cases-bin:
	mkdir test-cases-bin

test-cases-bin/%.bin: test-cases/%.bm test-cases-bin
	binmake $< $@

request-test: $(request_test_SRC:.cpp=.o)
	$(CXX) $(CXXFLAGS) -o $@ $^ -lboost_system -pthread

parse-test: $(parse_test_SRC:.cpp=.o)
	$(CXX) $(CXXFLAGS) -o $@ $^

parse-test-afl: $(parse_test_SRC:.cpp=.afl.o)
	AFL_HARDEN=1 $(AFL_CXX) $(CXXFLAGS) -o $@ $^

.PHONY: all clean

-include $(DEP)
