TARGET=packet
CXX=gcc
CXXFLAGS=-lpcap
OBJECTS=main.o

$(TARGET):$(OBJECTS)
	$(CXX)  -o $@ $^ $(CXXFLAGS)

main.o: main.c
	$(CXX)  -c $^ $(CXXFLAGS)

clean:
	rm $(OBJECTS) $(TARGET)