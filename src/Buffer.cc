#include <stdlib.h>
#include "Buffer.h"

namespace SMBx 
{		
	Buffer::Buffer()
	{	
		buffer = 0;
		buffer_len = 0;			
	}
	
	int Buffer::len() { return buffer_len; }
	const u_char* Buffer::data() { return buffer; }
	
	void Buffer::append(int len, const u_char* data, uint16 beginning)
	{
		auto size = (len-beginning) * sizeof(u_char);
		
		if (buffer == 0) {
			buffer = (u_char*)malloc(size);				
		} else {
			buffer = (u_char*)realloc(buffer, buffer_len*sizeof(u_char) + size);
		}
		
		memcpy(buffer + buffer_len, data + beginning, size);
		buffer_len = buffer_len + len - beginning;					
	}
	
	void Buffer::reset()
	{
		if (buffer != 0) 
			free(buffer);	
		
		buffer = 0;
		buffer_len = 0;			
	}
	
	Buffer::~Buffer()
	{
		reset();
	}
}