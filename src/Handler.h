#ifndef SMBx_HANDLER_H
#define SMBx_HANDLER_H

#include "Reader.h"
#include "Message.h"

namespace SMBx {
	class Analyzer;

	class Handler {
		protected:
			bool is_last_finished;
			bool is_last_parsed;
			uint16 beginning;
			uint16 buffer_len;
			u_char* buffer;
			Analyzer* analyzer;
			Reader* reader;
			SMB2_Message* current_message = NULL;
			
		public:
			Handler(Analyzer* a, Reader* r);
			void handle(int new_len, const u_char* new_data);
		
		protected:
			bool handle_new();
			void handle_continue();						
	};
}
#endif