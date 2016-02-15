all: appender.s host.c
	gcc -m32  -g appender.s -o /tmp/appender
	gcc -m32 host.c -o /tmp/host
	gcc -m32 detector.c -o detect/detector
	cp -r detect /tmp
	cp info.sh /tmp
	@echo -n "text size = "
	@size /tmp/appender | tail -n 1 | awk '{print $$1}'
	@echo -n "***********\n Now go to /tmp to run the virus \n*************\n" 

clean:
	rm host appender detect/detector *.o

