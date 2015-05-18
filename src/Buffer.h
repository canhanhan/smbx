#ifndef SMBx_BUFFER_H
#define SMBx_BUFFER_H

#include "NetVar.h"

namespace SMBx {
	class Buffer 
	{
		private:
		uint16 buffer_len;
		u_char* buffer;
		
		public:
		Buffer();
		~Buffer();
		
		int len();
		const u_char* data();
		
		void append(int len, const u_char* data, uint16 beginning=0);
		void reset();
	};
}

#endif