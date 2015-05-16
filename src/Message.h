#ifndef SMBx_MESSAGE_H
#define SMBx_MESSAGE_H

#include "Analyzer.h"
#include "Reader.h"

namespace SMBx 
{	
	class SMB2_Message 
	{
		protected:
		Analyzer* analyzer;
		Reader* reader;			
		
		public:
		SMB2_Message(Analyzer* a, Reader* r);
		virtual ~SMB2_Message() {};
		
		virtual bool New() { throw "Does not support";	}
		virtual bool Continue() { throw "Does not support";	}
	};
		
	class SMB2_Header : public SMB2_Message
	{
		public:
		uint16 beginning;
		uint16 header_size;
		uint32 status;
		uint16 command;
		uint32 flags;
		uint32 next_command;
		uint64 messageId;
		int32 treeId;
		uint64 sessionId;
		uint16 structure_size;	
		bool is_response;
		
		SMB2_Header(Analyzer* a, Reader* r, uint16 b) : SMB2_Message(a, r) {
			beginning = b;
		};
		
		virtual bool New();
	};
	
	class SMB2_Body : public SMB2_Message
	{
		protected:		
		val_list* create_value_list();
		
		public:
		SMB2_Header* header;
		
		SMB2_Body(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Message(a, r)
		{
			header = h;
		}
	};
	
	class SMB2_Chunked_Body : public SMB2_Body 
	{
		protected:
		uint16 data_offset;
		uint32 data_len;
		uint32 data_remaining;
		uint32 data_received;		
		virtual bool GetData();
		virtual void TriggerEvent() { throw 20; };
		virtual void ChunkReceived(uint32 length) { throw 21; };
		virtual void ChunkFailed() { throw 22; };
		
		public:
		SMB2_Chunked_Body(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}		
		virtual bool Continue();
	};	
	
	class SMB2_FileMessage : public SMB2_Chunked_Body 
	{
		private:
		std::string file_id;		
		
		protected:
		virtual void TriggerEvent();
		virtual void ChunkReceived(uint32 length);
		virtual void ChunkFailed();
		
		public:
		virtual bool New();
		SMB2_FileMessage(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Chunked_Body(a, r, h) {}
	};		
	
	class SMB2_Error : public SMB2_Body
	{
		protected:
		uint32 byte_count;
		
		public:		
		SMB2_Error(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}
		virtual bool New();
	};
		
	class SMB2_Negotiate_Request : public SMB2_Body
	{
		protected:
		VectorType* vector_of_count;
		uint16 dialect_count;
		uint16 security_mode;
		int32 capabilities;
		const char* client_guid = NULL;
		const uint16* dialects = NULL;
		VectorVal* dialectsVal = NULL;	
		
		public:	
		SMB2_Negotiate_Request(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {
			vector_of_count = new VectorType(base_type(TYPE_COUNT));
		}

		~SMB2_Negotiate_Request() {
			Unref(vector_of_count);	
		}
		
		virtual bool New();
	};
	
	class SMB2_Negotiate_Response : public SMB2_Body
	{
		private:
		uint16 security_mode;
		uint16 dialect; 
		const char* server_guid;
		uint32 capabilities;
		uint64 server_time;
		uint64 server_boot_time;
		uint16 buffer_offset;
		uint16 buffer_len;
		
		public:
		SMB2_Negotiate_Response(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}
		
		virtual bool New();
	};
	
	class SMB2_Session_Setup_Request : public SMB2_Body
	{
		private:
		uint8 flags;
		uint8 security_mode;
		uint32 capabilities;
		uint32 channel;
		uint16 buffer_offset;
		uint16 buffer_len;
		uint64 previous_session_id;	

		public:
		SMB2_Session_Setup_Request(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}
		
		virtual bool New();		
	};
	
	class SMB2_Session_Setup_Response : public SMB2_Body
	{
		private:
		uint16 flags;
		uint16 buffer_offset;
		uint16 buffer_len;
		
		public:
		SMB2_Session_Setup_Response(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}
		
		virtual bool New();			
	};
	
	class SMB2_Logoff_Request : public SMB2_Body
	{
		public:
		SMB2_Logoff_Request(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}		
		virtual bool New();					
	};
	
	class SMB2_Logoff_Response : public SMB2_Body
	{
		public:
		SMB2_Logoff_Response(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}		
		virtual bool New();					
	};
	
	class SMB2_Tree_Connect_Request : public SMB2_Body
	{
		private:
		uint16 path_offset;	
		uint16 path_length;
		
		public:
		SMB2_Tree_Connect_Request(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}		
		virtual bool New();					
	};
	
	class SMB2_Tree_Connect_Response : public SMB2_Body
	{
		private:
		uint8 share_type;
		uint32 share_flags;
		uint32 capabilities;
		uint32 maximal_access;
	
		public:
		SMB2_Tree_Connect_Response(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}		
		virtual bool New();					
	};	
	
	class SMB2_Tree_Disconnect_Request : public SMB2_Body
	{
		public:
		SMB2_Tree_Disconnect_Request(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}		
		virtual bool New();					
	};
	
	class SMB2_Tree_Disconnect_Response : public SMB2_Body
	{
		public:
		SMB2_Tree_Disconnect_Response(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}		
		virtual bool New();					
	};	

	class SMB2_Create_Request : public SMB2_Body
	{
		private:
		uint8 oplock;
		uint32 impersonation_level;
		uint64 flags;
		uint32 access_mask;
		uint32 file_attrs;
		uint32 share_access;
		uint32 disposition;
		uint32 create_options;
		uint16 filename_offset;
		uint16 filename_len;
		uint32 context_offset;
		uint32 context_len;
		BroString* filename;
		
		public:
		SMB2_Create_Request(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}		
		virtual bool New();					
	};
	
	class SMB2_Create_Response : public SMB2_Body
	{
		private:
		uint8 oplock;
		uint32 create_action;
		uint64 creation_time;
		uint64 last_access_time;
		uint64 last_write_time;
		uint64 change_time;
		uint64 alloc_size;
		uint64 eof;
		uint32 file_attrs;
		uint64 persistent_file_id;
		uint64 volatile_file_id;
		uint32 context_offset;
		uint32 context_len;		
		
		public:
		SMB2_Create_Response(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}		
		virtual bool New();					
	};
	
	class SMB2_Close_Request : public SMB2_Body
	{
		private:
		uint16 flags;
		uint64 persistent_file_id;
		uint64 volatile_file_id;
	
		public:
		SMB2_Close_Request(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}		
		virtual bool New();					
	};
	
	class SMB2_Close_Response : public SMB2_Body
	{
		private:
		uint16 flags;
		uint64 creation_time;
		uint64 last_access_time;
		uint64 last_write_time;
		uint64 change_time;
		uint64 alloc_size;
		uint64 eof;
		uint32 file_attrs;
	
		public:
		SMB2_Close_Response(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}		
		virtual bool New();					
	};		
	
	class SMB2_Read_Request : public SMB2_Body
	{
		private:
		uint8 flags;
		uint32 length;
		uint64 offset;
		uint64 persistent_file_id;
		uint64 volatile_file_id;
		uint32 minimum_count;
		uint32 channel;
		uint32 remaining_bytes;
		uint16 channel_info_offset;
		uint16 channel_info_len;		
		
		public:
		SMB2_Read_Request(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}		
		virtual bool New();					
	};
	
	
	class SMB2_Read_Response : public SMB2_FileMessage
	{	
		protected:
		virtual void TriggerEvent();
		
		public:
		SMB2_Read_Response(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_FileMessage(a, r, h) {}		
		virtual bool New();
	
	};		
	
	class SMB2_Write_Request : public SMB2_FileMessage
	{
		private:
		uint64 offset;
		uint64 persistent_file_id;
		uint64 volatile_file_id;
		uint32 channel;
		uint16 channel_info_offset;
		uint16 channel_info_len;
		uint32 flags;

		protected:
		virtual void TriggerEvent();
		
		public:
		SMB2_Write_Request(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_FileMessage(a, r, h) {}		
		virtual bool New();
	};
	
	class SMB2_Write_Response : public SMB2_Body
	{
		private:
		uint32 byte_count;
		uint32 remaining;
		uint16 channel_info_offset;
		uint16 channel_info_len;
		
		public:
		SMB2_Write_Response(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}		
		virtual bool New();					
	};	

	class SMB2_Cancel_Request : public SMB2_Body
	{
		public:
		SMB2_Cancel_Request(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}		
		virtual bool New();					
	};
	
	class SMB2_Cancel_Response : public SMB2_Body
	{
		public:
		SMB2_Cancel_Response(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}		
		virtual bool New();					
	};	

	class SMB2_Query_Directory_Request : public SMB2_Body
	{
		private:
		uint8 info_class;
		uint8 flags;
		uint32 file_index;
		uint64 persistent_file_id;
		uint64 volatile_file_id;
		uint16 filename_offset;
		uint16 filename_len;
		uint32 output_buffer_len;
		BroString* filename;
		
		public:
		SMB2_Query_Directory_Request(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Body(a, r, h) {}		
		virtual bool New();					
	};
	
	class SMB2_Query_Directory_Response : public SMB2_Chunked_Body
	{	
		protected:
		virtual void TriggerEvent();
		virtual void ChunkReceived(uint32 length);
		virtual void ChunkFailed();
	
		public:
		SMB2_Query_Directory_Response(Analyzer* a, Reader* r, SMB2_Header* h) : SMB2_Chunked_Body(a, r, h) {}		
		virtual bool New();			
	};	
	
}
	
#endif