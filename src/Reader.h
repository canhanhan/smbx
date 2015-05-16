#ifndef SMBx_READER_H
#define SMBx_READER_H

#include "NetVar.h"

namespace SMBx {
	const static int uuid_index[] = { 3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15 };		
	class Reader {
		public:	
			uint16 current_pos;
			uint16 len;
			const u_char* data;	

			template<typename t> const t* read()
			{
				return read<t>(1);
			}					
			
			template<typename t> const t* read(uint count)
			{
				size_t size = sizeof(t) * count;
				check_boundry(size);
				
				uint16 last_pos = current_pos;
				current_pos+=size;

				return (const t*)(data+last_pos);
			}
	
			// Taken from analyzer::dce_rpc
			const char* read_uuid() {
				check_boundry(16);
				
				static char s[1024];
				char* sp = s;

				for ( int i = 0; i < 16; ++i ) {
					if ( i == 4 || i == 6 || i == 8 || i == 10 )
						sp += snprintf(sp, s + sizeof(s) - sp, "-");

					int j = uuid_index[i] + current_pos;
					sp += snprintf(sp, s + sizeof(s) - sp, "%02x", data[j]);
				}
				
				current_pos += 16;
				return s;
			}
			
			BroString* read_string(uint length)
			{
				check_boundry(length);			
				u_char* buf = new u_char[length];
			
				for(uint i = 0; i < length; i++) {
					buf[i] = (u_char)(*read<uint16>() & 0xff);
				}

				return new BroString(buf, length, 0);
			}
			
			void check_boundry(uint length) 
			{
				if (current_pos + length > len) {
					printf("Buffer is not enough to read the datagram. Requested: %u, Available: %d, Position: %d\n", length, len-current_pos, current_pos);
					throw 20;
				}		
			}	
			
			void move_end() 
			{
				current_pos = len;
			}
			
			void skip(int bytes) 
			{
				check_boundry(bytes);
				current_pos += bytes;
			}	
			
			void reset(int new_len, const u_char* new_data)
			{
				data = new_data;
				len = new_len;
				current_pos = 0;	
			}
	};
}

#endif