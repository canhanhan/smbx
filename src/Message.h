#ifndef SMBx_MESSAGE_H
#define SMBx_MESSAGE_H

#include <memory>
#include <stdexcept>

#include "Reader.h"
#include "AnalyzerContext.h"

namespace SMBx
{
	class Analyzer;

	class SMB2_Header
	{
		public:
		uint16 beginning;
		uint32 protocolId;
		uint16 header_size;
		uint32 status;
		uint16 command;
		uint32 flags;
		uint32 next_command;
		uint64 messageId;
		uint32 treeId;
		uint64 sessionId;
		uint16 structure_size;
		bool is_response;
		bool is_async;

		virtual bool New(Reader& reader);
	};

	class SMB2_Body
	{
		protected:
		val_list* create_value_list(AnalyzerContext& context);

		public:
		bool is_parsed { true };
		shared_ptr<SMB2_Header> header;

		SMB2_Body(shared_ptr<SMB2_Header> h) : header(h) { }
		virtual ~SMB2_Body() {};

		virtual bool New(AnalyzerContext& context, Reader& reader) = 0;
		virtual bool Continue(AnalyzerContext& context, Reader& reader) { throw std::runtime_error("This message type does not have chunked data"); }
	};

	class SMB2_Response
	{
		public:
		shared_ptr<SMB2_Body> request_;

		shared_ptr<SMB2_Body> request() { return request_; }
		template<typename T> shared_ptr<T> request() { return dynamic_pointer_cast<T>(request_); }

		SMB2_Response(shared_ptr<SMB2_Body> r) : request_(r) {}
	};

	class SMB2_Chunked_Body : public SMB2_Body
	{
		public:
		uint16 data_offset = 0;
		uint32 data_len = 0;
		uint32 data_remaining = 0;
		uint32 data_received = 0;

		protected:
		virtual void Finished(AnalyzerContext& context, Reader& reader) { };
		virtual void ChunkReceived(AnalyzerContext& context, Reader& reader, uint32 length) { };
		virtual void ChunkFailed(AnalyzerContext& context, Reader& reader) { };

		public:
		SMB2_Chunked_Body(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
		virtual bool Continue(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_FileMessage : public SMB2_Chunked_Body
	{
		private:
		shared_ptr<SMB2_File> file_;

		protected:
		virtual void ChunkReceived(AnalyzerContext& context, Reader& reader, uint32 length) override;
		virtual void ChunkFailed(AnalyzerContext& context, Reader& reader) override;

		public:
		uint64 offset = 0;
		uint64 volatile_file_id = 0;

		SMB2_FileMessage(shared_ptr<SMB2_Header> h) : SMB2_Chunked_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Error : public SMB2_Body, SMB2_Response
	{
		public:
		uint32 byte_count;

		SMB2_Error(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Body(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Negotiate_Request : public SMB2_Body
	{
		public:
		VectorType* vector_of_count = new VectorType(base_type(TYPE_COUNT));
		uint16 dialect_count;
		uint16 security_mode;
		int32 capabilities;
		const char* client_guid = NULL;
		const uint16* dialects = NULL;
		VectorVal* dialectsVal = NULL;

		SMB2_Negotiate_Request(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		~SMB2_Negotiate_Request() { Unref(vector_of_count);	 }

		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Negotiate_Response : public SMB2_Chunked_Body, public SMB2_Response
	{
		protected:
		void ChunkReceived(AnalyzerContext& context, Reader& reader, uint32 length) override final;
		void Finished(AnalyzerContext& context, Reader& reader) override final;

		public:
		uint16 security_mode;
		uint16 dialect;
		const char* server_guid;
		uint32 capabilities;
		uint64 server_time;
		uint64 server_boot_time;

		SMB2_Negotiate_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Chunked_Body(h), SMB2_Response(req) {}

		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Session_Setup_Request : public SMB2_Chunked_Body
	{
		protected:
		void ChunkReceived(AnalyzerContext& context, Reader& reader, uint32 length) override final;
		void Finished(AnalyzerContext& context, Reader& reader) override final;

		public:
		uint8 flags;
		uint8 security_mode;
		uint32 capabilities;
		uint32 channel;
		uint64 previous_session_id;

		SMB2_Session_Setup_Request(shared_ptr<SMB2_Header> h) : SMB2_Chunked_Body(h) {}

		virtual bool New(AnalyzerContext& context, Reader& reader);
	};

	class SMB2_Session_Setup_Response : public SMB2_Chunked_Body, public SMB2_Response
	{
		protected:
		void ChunkReceived(AnalyzerContext& context, Reader& reader, uint32 length) override final;
		void Finished(AnalyzerContext& context, Reader& reader) override final;

		public:
		uint16 flags;

		SMB2_Session_Setup_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Chunked_Body(h), SMB2_Response(req) {}

		virtual bool New(AnalyzerContext& context, Reader& reader);
	};

	class SMB2_Logoff_Request : public SMB2_Body
	{
		public:
		SMB2_Logoff_Request(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Logoff_Response : public SMB2_Body, public SMB2_Response
	{
		public:
		SMB2_Logoff_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Body(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Tree_Connect_Request : public SMB2_Body
	{
		public:
		uint16 path_offset;
		uint16 path_length;
		string name;

		SMB2_Tree_Connect_Request(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Tree_Connect_Response : public SMB2_Body, public SMB2_Response
	{
		public:
		uint8 share_type;
		uint32 share_flags;
		uint32 capabilities;
		uint32 maximal_access;

		SMB2_Tree_Connect_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Body(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Tree_Disconnect_Request : public SMB2_Body
	{
		public:
		SMB2_Tree_Disconnect_Request(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Tree_Disconnect_Response : public SMB2_Body, public SMB2_Response
	{
		public:
		SMB2_Tree_Disconnect_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Body(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Create_Request : public SMB2_Body
	{
		public:
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
		string filename;

		SMB2_Create_Request(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Create_Response : public SMB2_Body, public SMB2_Response
	{
		public:
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

		SMB2_Create_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Body(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Close_Request : public SMB2_Body
	{
		public:
		uint16 flags;
		uint64 persistent_file_id;
		uint64 volatile_file_id;

		SMB2_Close_Request(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Close_Response : public SMB2_Body, public SMB2_Response
	{
		public:
		uint16 flags;
		uint64 creation_time;
		uint64 last_access_time;
		uint64 last_write_time;
		uint64 change_time;
		uint64 alloc_size;
		uint64 eof;
		uint32 file_attrs;

		SMB2_Close_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Body(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Read_Request : public SMB2_Body
	{
		public:
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

		SMB2_Read_Request(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};


	class SMB2_Read_Response : public SMB2_FileMessage, public SMB2_Response
	{
		public:
		SMB2_Read_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_FileMessage(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Write_Request : public SMB2_FileMessage
	{
		public:
		uint64 persistent_file_id;
		uint32 channel;
		uint16 channel_info_offset;
		uint16 channel_info_len;
		uint32 flags;

		public:
		SMB2_Write_Request(shared_ptr<SMB2_Header> h) : SMB2_FileMessage(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Write_Response : public SMB2_Body, public SMB2_Response
	{
		public:
		uint32 byte_count;
		uint32 remaining;
		uint16 channel_info_offset;
		uint16 channel_info_len;

		SMB2_Write_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Body(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Cancel_Request : public SMB2_Body
	{
		public:
		SMB2_Cancel_Request(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Cancel_Response : public SMB2_Body, public SMB2_Response
	{
		public:
		SMB2_Cancel_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Body(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Query_Directory_Request : public SMB2_Body
	{
		public:
		uint8 info_class;
		uint8 flags;
		uint32 file_index;
		uint64 persistent_file_id;
		uint64 volatile_file_id;
		uint16 filename_offset;
		uint16 filename_len;
		uint32 output_buffer_len;

		SMB2_Query_Directory_Request(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Query_Directory_Response : public SMB2_Chunked_Body, public SMB2_Response
	{
		protected:
		void Finished(AnalyzerContext& context, Reader& reader) override final;
		void ChunkReceived(AnalyzerContext& context, Reader& reader, uint32 length) override final;

		public:
		SMB2_Query_Directory_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Chunked_Body(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Flush_Request : public SMB2_Body
	{
		public:
		uint64 persistent_file_id;
		uint64 volatile_file_id;

		SMB2_Flush_Request(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Flush_Response : public SMB2_Body, public SMB2_Response
	{
		public:
		SMB2_Flush_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Body(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Lock_Request : public SMB2_Body
	{
		public:
		uint16 lock_count;
		uint32 lock_sequence;
		uint64 persistent_file_id;
		uint64 volatile_file_id;

		SMB2_Lock_Request(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Lock_Response : public SMB2_Body, public SMB2_Response
	{
		public:
		SMB2_Lock_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Body(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Echo_Request : public SMB2_Body
	{
		public:
		SMB2_Echo_Request(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Echo_Response : public SMB2_Body, public SMB2_Response
	{
		public:
		SMB2_Echo_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Body(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Change_Notify_Request : public SMB2_Body
	{
		public:
		uint16 flags;
		uint32 output_buffer_length;
		uint64 persistent_file_id;
		uint64 volatile_file_id;
		uint32 completion_filter;

		SMB2_Change_Notify_Request(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Change_Notify_Response : public SMB2_Body, public SMB2_Response
	{
		public:
		uint16 output_buffer_offset;
		uint32 output_buffer_length;

		SMB2_Change_Notify_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Body(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Query_Info_Request : public SMB2_Body
	{
		public:
		u_char info_type;
		u_char file_info_class;
		uint32 output_buffer_length;
		uint16 input_buffer_offset;
		uint32 input_buffer_length;
		uint32 additional_information;
		uint32 flags;
		uint64 persistent_file_id;
		uint64 volatile_file_id;

		SMB2_Query_Info_Request(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Query_Info_Response : public SMB2_Body, public SMB2_Response
	{
		public:
		uint16 output_buffer_offset;
		uint32 output_buffer_length;

		SMB2_Query_Info_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Body(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Set_Info_Request : public SMB2_Body
	{
		public:
		u_char info_type;
		u_char file_info_class;
		uint32 buffer_length;
		uint16 buffer_offset;
		uint32 additional_information;
		uint64 persistent_file_id;
		uint64 volatile_file_id;

		SMB2_Set_Info_Request(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Set_Info_Response : public SMB2_Body, public SMB2_Response
	{
		public:
		SMB2_Set_Info_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Body(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Ioctl_Request : public SMB2_Body
	{
		public:
		uint32 ctl_code;
		uint64 persistent_file_id;
		uint64 volatile_file_id;
		uint32 input_offset;
		uint32 input_count;
		uint32 max_input_response;
		uint32 output_offset;
		uint32 output_count;
		uint32 max_output_response;
		uint32 flags;

		SMB2_Ioctl_Request(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Ioctl_Response : public SMB2_Body, public SMB2_Response
	{
		public:
		uint32 ctl_code;
		uint64 persistent_file_id;
		uint64 volatile_file_id;
		uint32 input_offset;
		uint32 input_count;
		uint32 output_offset;
		uint32 output_count;
		uint32 flags;

		SMB2_Ioctl_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Body(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Oplock_Break_Request : public SMB2_Body
	{
		public:
		SMB2_Oplock_Break_Request(shared_ptr<SMB2_Header> h) : SMB2_Body(h) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};

	class SMB2_Oplock_Break_Response : public SMB2_Body, public SMB2_Response
	{
		public:
		SMB2_Oplock_Break_Response(shared_ptr<SMB2_Header> h, shared_ptr<SMB2_Body> req) : SMB2_Body(h), SMB2_Response(req) {}
		virtual bool New(AnalyzerContext& context, Reader& reader) override;
	};
}
#endif
