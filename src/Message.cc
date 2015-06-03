#define TIMESTAMP(d) (double)(d > 0 ? (d / 10000000) - 11644473600 : 0)

#include <sstream>
#include <string>
#include "Event.h"
#include "Message.h"
#include "binpac_bytestring.h"
#include "file_analysis/Manager.h"

namespace SMBx
{
	const static EventHandlerPtr smb2_negotiate_request = internal_handler("smb2_negotiate_request");
	const static EventHandlerPtr smb2_negotiate_response = internal_handler("smb2_negotiate_response");
	const static EventHandlerPtr smb2_session_setup_request = internal_handler("smb2_session_setup_request");
	const static EventHandlerPtr smb2_session_setup_response = internal_handler("smb2_session_setup_response");
	const static EventHandlerPtr smb2_logoff_request = internal_handler("smb2_logoff_request");
	const static EventHandlerPtr smb2_logoff_response = internal_handler("smb2_logoff_response");
	const static EventHandlerPtr smb2_treeconnect_request = internal_handler("smb2_treeconnect_request");
	const static EventHandlerPtr smb2_treeconnect_response = internal_handler("smb2_treeconnect_response");
	const static EventHandlerPtr smb2_tree_disconnect_request = internal_handler("smb2_tree_disconnect_request");
	const static EventHandlerPtr smb2_tree_disconnect_response = internal_handler("smb2_tree_disconnect_response");
	const static EventHandlerPtr smb2_create_request = internal_handler("smb2_create_request");
	const static EventHandlerPtr smb2_create_response = internal_handler("smb2_create_response");
	const static EventHandlerPtr smb2_close_request = internal_handler("smb2_close_request");
	const static EventHandlerPtr smb2_close_response = internal_handler("smb2_close_response");
	const static EventHandlerPtr smb2_read_request = internal_handler("smb2_read_request");
	const static EventHandlerPtr smb2_read_response = internal_handler("smb2_read_response");
	const static EventHandlerPtr smb2_write_request = internal_handler("smb2_write_request");
	const static EventHandlerPtr smb2_write_response = internal_handler("smb2_write_response");
	const static EventHandlerPtr smb2_cancel_request = internal_handler("smb2_cancel_request");
	const static EventHandlerPtr smb2_cancel_response = internal_handler("smb2_cancel_response");
	const static EventHandlerPtr smb2_query_directory_request = internal_handler("smb2_query_directory_request");
	const static EventHandlerPtr smb2_query_directory_response = internal_handler("smb2_query_directory_response");
	const static EventHandlerPtr smb2_flush_request = internal_handler("smb2_flush_request");
	const static EventHandlerPtr smb2_flush_response = internal_handler("smb2_flush_response");
	const static EventHandlerPtr smb2_lock_request = internal_handler("smb2_lock_request");
	const static EventHandlerPtr smb2_lock_response = internal_handler("smb2_lock_response");
	const static EventHandlerPtr smb2_echo_request = internal_handler("smb2_echo_request");
	const static EventHandlerPtr smb2_echo_response = internal_handler("smb2_echo_response");
	const static EventHandlerPtr smb2_change_notify_request = internal_handler("smb2_change_notify_request");
	const static EventHandlerPtr smb2_change_notify_response = internal_handler("smb2_change_notify_response");
	const static EventHandlerPtr smb2_query_info_request = internal_handler("smb2_query_info_request");
	const static EventHandlerPtr smb2_query_info_response = internal_handler("smb2_query_info_response");
	const static EventHandlerPtr smb2_set_info_request = internal_handler("smb2_set_info_request");
	const static EventHandlerPtr smb2_set_info_response = internal_handler("smb2_set_info_response");
	const static EventHandlerPtr smb2_ioctl_request = internal_handler("smb2_ioctl_request");
	const static EventHandlerPtr smb2_ioctl_response = internal_handler("smb2_ioctl_response");
	const static EventHandlerPtr smb2_oplock_break_request = internal_handler("smb2_oplock_break_request");
	const static EventHandlerPtr smb2_oplock_break_response = internal_handler("smb2_oplock_break_response");
	const static EventHandlerPtr smb2_error = internal_handler("smb2_error");
	const static EventHandlerPtr smb2_pre_file_transfer = internal_handler("smb2_pre_file_transfer");

	static RecordType* smb2_header;
	static RecordType* smb2_fileinfo;

	bool SMB2_Header::New(Reader& reader)
	{
		beginning = reader.current_pos;
		protocolId = *reader.read<uint32>();
		header_size = *reader.read<uint16>();
		reader.skip(2);
		status =  *reader.read<uint32>();
		command = *reader.read<uint16>();
		reader.skip(2);
		flags = *reader.read<uint32>();
		next_command = *reader.read<uint32>();
		messageId = *reader.read<uint64>();
		reader.skip(4);
		treeId = *reader.read<uint32>();
		sessionId = *reader.read<uint64>();
		reader.skip(16);
		structure_size = *reader.read<uint16>();
		is_response = flags & 0x00000001;
		is_async = flags & 0x00000002;

		return true;
	}

	val_list* SMB2_Body::create_value_list(AnalyzerContext& context)
	{
		if (smb2_header == NULL)
			 smb2_header = internal_type("smb2_header")->AsRecordType();

		auto rv = new RecordVal(smb2_header);
		rv->Assign(0, new Val(header->header_size, TYPE_COUNT));
		rv->Assign(1, new Val(header->status, TYPE_COUNT));
		rv->Assign(2, new Val(header->command, TYPE_COUNT));
		rv->Assign(3, new Val(header->flags, TYPE_COUNT));
		rv->Assign(4, new Val(header->messageId, TYPE_COUNT));
		rv->Assign(5, new Val(header->treeId, TYPE_COUNT));
		rv->Assign(6, new Val(header->sessionId, TYPE_COUNT));
		rv->Assign(7, new Val(header->structure_size, TYPE_COUNT));

		auto vl = new val_list;
		vl->append(context.conn->BuildConnVal());
		vl->append(rv);

		return vl;
	}

	bool SMB2_Chunked_Body::New(AnalyzerContext& context, Reader& reader)
	{
		if (data_len > 0)
		{
			reader.skip(data_offset - reader.current_pos + header->beginning);
			ASSERT(reader.len >= reader.current_pos);
			uint16 remaining = reader.len - reader.current_pos;
			data_received = remaining;

			printf("Data len: %u, off: %hu, pos: %hu, beg: %hu\n", data_len, data_offset, reader.current_pos, header->beginning);
			printf("Data rem %hu\n", remaining);

			if (data_len > remaining)
  			{
				ChunkReceived(context, reader, remaining);
				return false;
			}

			ChunkReceived(context, reader, data_len);
		}

		Finished(context, reader);

		return true;
	}

	bool SMB2_Chunked_Body::Continue(AnalyzerContext& context, Reader& reader)
	{
		auto remaining = std::min(data_len - data_received, (uint32)reader.len);
		data_received += remaining;

		DEBUG_MSG("Received %u-%u-%u\n", data_len, data_received, remaining);
		ChunkReceived(context, reader, remaining);

		if (data_received < data_len)
			return false;

		if (data_received > data_len)
			ChunkFailed(context, reader);

		DEBUG_MSG("Finished\n");
		Finished(context, reader);

		return true;
	}

	bool SMB2_FileMessage::New(AnalyzerContext& context, Reader& reader)
	{
		if (smb2_fileinfo == NULL)
			 smb2_fileinfo = internal_type("smb2_fileinfo")->AsRecordType();

		if (file_ == nullptr)
			file_ = context.state.GetFile(header->sessionId, header->treeId, volatile_file_id);

		if (file_ != nullptr && smb2_pre_file_transfer) {
			auto rv = new RecordVal(smb2_fileinfo);
			rv->Assign(0, new StringVal(new BroString(file_->file_id)));
			rv->Assign(1, new StringVal(new BroString(file_->name)));
			rv->Assign(2, new StringVal(new BroString(file_->tree_name)));
			rv->Assign(3, new StringVal(new BroString(file_->path)));

			auto vl = create_value_list(context);
			vl->append(rv);

			context.QueueEvent(smb2_pre_file_transfer, vl);
		}

		return SMB2_Chunked_Body::New(context, reader);
	}

	void SMB2_FileMessage::ChunkReceived(AnalyzerContext& context, Reader& reader, uint32 length)
	{
		if (file_ != nullptr)
			file_->file_id = file_mgr->DataIn(reader.read<uint8>(length), length, offset + data_received - length, context.tag, context.conn, !header->is_response, file_->file_id);
		else
			reader.skip(length);
	}

	void SMB2_FileMessage::ChunkFailed(AnalyzerContext& context, Reader& reader)
	{
		DEBUG_MSG("Missed part of a file... (File length: %u, Collected: %u)\n", data_len, data_received);
		if (file_ != nullptr)
			file_mgr->IgnoreFile(file_->file_id);

		reader.skip(data_received);
	}

	bool SMB2_Error::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(2);
		byte_count = *reader.read<uint32>();

		reader.skip(byte_count || 1);

		if (smb2_error) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_error, vl);
		}

		return true;
	}

	bool SMB2_Negotiate_Request::New(AnalyzerContext& context, Reader& reader)
	{
		dialect_count = *reader.read<uint16>();
		security_mode = *reader.read<uint16>();
		reader.skip(2);
		capabilities = *reader.read<uint32>();
		client_guid = reader.read_uuid();
		reader.skip(8);

		if (!reader.available(dialect_count * sizeof(uint16)))
		{
			is_parsed = false;
			return false;
		}

		dialects = reader.read<uint16>(dialect_count);
		dialectsVal = new VectorVal(vector_of_count);
		for(uint i=0; i < dialect_count; i++)
			dialectsVal->Assign(i, new Val(dialects[i], TYPE_COUNT));

		if (smb2_negotiate_request) {
			auto vl = create_value_list(context);
			vl->append(new Val(security_mode, TYPE_COUNT));
			vl->append(new Val(capabilities, TYPE_COUNT));
			vl->append(new StringVal(client_guid));
			vl->append(dialectsVal);

			context.QueueEvent(smb2_negotiate_request, vl);
		}

		return true;
	}

	bool SMB2_Negotiate_Response::New(AnalyzerContext& context, Reader& reader)
	{
		security_mode = *reader.read<uint16>();
		dialect = *reader.read<uint16>();
		reader.skip(2);
		server_guid = reader.read_uuid();
		capabilities = *reader.read<uint32>();
		reader.skip(12);
		server_time = *reader.read<uint64>();
		server_boot_time = *reader.read<uint64>();
		data_offset = *reader.read<uint16>();
		data_len = *reader.read<uint16>();
		reader.skip(4);

		return SMB2_Chunked_Body::New(context, reader);
	}

	void SMB2_Negotiate_Response::Finished(AnalyzerContext& context, Reader& reader)
	{
		if (smb2_negotiate_response) {
			auto vl = create_value_list(context);
			vl->append(new Val(security_mode, TYPE_COUNT));
			vl->append(new Val(dialect, TYPE_COUNT));
			vl->append(new StringVal(server_guid));
			vl->append(new Val(capabilities, TYPE_COUNT));
			vl->append(new Val(TIMESTAMP(server_time), TYPE_TIME));
			vl->append(new Val(TIMESTAMP(server_boot_time), TYPE_TIME));

			context.QueueEvent(smb2_negotiate_response, vl);
		}
	}

	void SMB2_Negotiate_Response::ChunkReceived(AnalyzerContext& context, Reader& reader, uint32 length)
	{
		reader.skip(length);
	}

	bool SMB2_Session_Setup_Request::New(AnalyzerContext& context, Reader& reader)
	{
		flags = *reader.read<uint8>();
		security_mode = *reader.read<uint8>();
		capabilities = *reader.read<uint32>();
		channel = *reader.read<uint32>();
		data_offset = *reader.read<uint16>();
		data_len = *reader.read<uint16>();
		previous_session_id = *reader.read<uint64>();

		return SMB2_Chunked_Body::New(context, reader);
	}

	void SMB2_Session_Setup_Request::Finished(AnalyzerContext& context, Reader& reader)
	{
		if (smb2_session_setup_request) {
			auto vl = create_value_list(context);
			vl->append(new Val(flags, TYPE_COUNT));
			vl->append(new Val(security_mode, TYPE_COUNT));
			vl->append(new Val(capabilities, TYPE_COUNT));
			vl->append(new Val(channel, TYPE_COUNT));
			vl->append(new Val(previous_session_id, TYPE_COUNT));
			vl->append(new Val(data_len, TYPE_COUNT));

			context.QueueEvent(smb2_session_setup_request, vl);
		}
	}

	void SMB2_Session_Setup_Request::ChunkReceived(AnalyzerContext& context, Reader& reader, uint32 length)
	{
		reader.skip(length);
	}

	bool SMB2_Session_Setup_Response::New(AnalyzerContext& context, Reader& reader)
	{
		flags = *reader.read<uint16>();
		data_offset = *reader.read<uint16>();
		data_len = *reader.read<uint16>();

		return SMB2_Chunked_Body::New(context, reader);
	}

	void SMB2_Session_Setup_Response::Finished(AnalyzerContext& context, Reader& reader)
	{
		context.state.NewSession(header->sessionId);

		if (smb2_session_setup_response) {
			auto vl = create_value_list(context);
			vl->append(new Val(flags, TYPE_COUNT));
			vl->append(new Val(data_len, TYPE_COUNT));

			context.QueueEvent(smb2_session_setup_response, vl);
		}
	}

	void SMB2_Session_Setup_Response::ChunkReceived(AnalyzerContext& context, Reader& reader, uint32 length)
	{
		reader.skip(length);
	}

	bool SMB2_Logoff_Request::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(2);

		context.state.CloseSession(header->sessionId);

		if (smb2_logoff_request) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_logoff_request, vl);
		}

		return true;
	}

	bool SMB2_Logoff_Response::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(2);

		if (smb2_logoff_response) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_logoff_response, vl);
		}

		return true;
	}

	bool SMB2_Tree_Connect_Request::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(2);
		path_offset = *reader.read<uint16>();
		path_length = *reader.read<uint16>();

		if (path_length > 0) {
			auto path_buffer_offset = path_offset - reader.current_pos + header->beginning;
			if (!reader.available(path_buffer_offset + path_length))
			{
				is_parsed = false;
				return false;
			}

			reader.skip(path_buffer_offset);
		}

		name = reader.read_string(path_length);
		if (smb2_treeconnect_request) {
			auto vl = create_value_list(context);
			vl->append(new StringVal(name));
			context.QueueEvent(smb2_treeconnect_request, vl);
		}

		return true;
	}

	bool SMB2_Tree_Connect_Response::New(AnalyzerContext& context, Reader& reader)
	{
		share_type = *reader.read<uint8>();
		reader.skip(1);
		share_flags = *reader.read<uint32>();
		capabilities = *reader.read<uint32>();
		maximal_access = *reader.read<uint32>();

		auto req = request<SMB2_Tree_Connect_Request>();
		if (req != nullptr)
			context.state.NewTreeConnection(header->sessionId, header->treeId, req->name);

		if (smb2_treeconnect_response) {
			auto vl = create_value_list(context);
			vl->append(new Val(share_flags, TYPE_COUNT));
			vl->append(new Val(capabilities, TYPE_COUNT));
			vl->append(new Val(maximal_access, TYPE_COUNT));

			context.QueueEvent(smb2_treeconnect_response, vl);
		}

		return true;
	}

	bool SMB2_Tree_Disconnect_Request::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(2);
		context.state.CloseTreeConnection(header->sessionId, header->treeId);

		if (smb2_tree_disconnect_request) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_tree_disconnect_request, vl);
		}

		return true;
	}

	bool SMB2_Tree_Disconnect_Response::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(2);

		if (smb2_tree_disconnect_response) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_tree_disconnect_response, vl);
		}

		return true;
	}

	bool SMB2_Create_Request::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(1);
		oplock = *reader.read<uint8>();
		impersonation_level = *reader.read<uint32>();
		flags = *reader.read<uint64>();
		reader.skip(8);
		access_mask = *reader.read<uint32>();
		file_attrs = *reader.read<uint32>();
		share_access = *reader.read<uint32>();
		disposition = *reader.read<uint32>();
		create_options = *reader.read<uint32>();
		filename_offset = *reader.read<uint16>();
		filename_len = *reader.read<uint16>();
		context_offset = *reader.read<uint32>();
		context_len = *reader.read<uint32>();

		if (filename_len > 0) {
			auto filename_buffer_offset = filename_offset - reader.current_pos + header->beginning;
			if (!reader.available(filename_buffer_offset + filename_len))
			{
				is_parsed = false;
				return false;
			}

			reader.skip(filename_buffer_offset);
			filename = reader.read_string(filename_len);
		}

		if (context_len > 0) {
			auto context_buffer_offset = context_offset - reader.current_pos + header->beginning;
			if (!reader.available(context_buffer_offset + context_len))
			{
				is_parsed = false;
				return false;
			}

			reader.skip(context_buffer_offset);
			reader.skip(context_len);
		}

		if (smb2_create_request) {
			auto vl = create_value_list(context);
			vl->append(new Val(access_mask, TYPE_COUNT));
			vl->append(new Val(file_attrs, TYPE_COUNT));
			vl->append(new Val(share_access, TYPE_COUNT));
			vl->append(new Val(disposition, TYPE_COUNT));
			vl->append(new Val(create_options, TYPE_COUNT));
			vl->append(new StringVal(filename));

			context.QueueEvent(smb2_create_request, vl);
		}

		return true;
	}

	bool SMB2_Create_Response::New(AnalyzerContext& context, Reader& reader)
	{
		oplock = *reader.read<uint8>();
		reader.skip(1);
		create_action = *reader.read<uint32>();
		creation_time = *reader.read<uint64>();
		last_access_time = *reader.read<uint64>();
		last_write_time = *reader.read<uint64>();
		change_time = *reader.read<uint64>();
		alloc_size = *reader.read<uint64>();
		eof = *reader.read<uint64>();
		file_attrs = *reader.read<uint32>();
		reader.skip(4);
		persistent_file_id = *reader.read<uint64>();
		volatile_file_id = *reader.read<uint64>();
		context_offset = *reader.read<uint32>();
		context_len = *reader.read<uint32>();

		if (context_len > 0) {
			auto context_buffer_offset = context_offset - reader.current_pos + header->beginning;
			if (!reader.available(context_buffer_offset + context_len))
			{
				is_parsed = false;
				return false;
			}

			reader.skip(context_buffer_offset);
			reader.skip(context_len);
		}

		auto req = request<SMB2_Create_Request>();
		if (req != nullptr)
			context.state.NewFile(header->sessionId, request()->header->treeId, volatile_file_id, req->filename);

		if (smb2_create_response) {
			auto vl = create_value_list(context);
			vl->append(new Val(create_action, TYPE_COUNT));
			vl->append(new Val(TIMESTAMP(creation_time), TYPE_TIME));
			vl->append(new Val(TIMESTAMP(last_access_time), TYPE_TIME));
			vl->append(new Val(TIMESTAMP(last_write_time), TYPE_TIME));
			vl->append(new Val(TIMESTAMP(change_time), TYPE_TIME));
			vl->append(new Val(alloc_size, TYPE_COUNT));
			vl->append(new Val(eof, TYPE_COUNT));
			vl->append(new Val(file_attrs, TYPE_COUNT));

			context.QueueEvent(smb2_create_response, vl);
		}

		return true;
	}

	bool SMB2_Close_Request::New(AnalyzerContext& context, Reader& reader)
	{
		flags = *reader.read<uint16>();
		reader.skip(4);
		persistent_file_id = *reader.read<uint64>();
		volatile_file_id = *reader.read<uint64>();

		context.state.CloseFile(header->sessionId, header->treeId, volatile_file_id);

		if (smb2_close_request) {
			auto vl = create_value_list(context);
			vl->append(new Val(flags, TYPE_COUNT));

			context.QueueEvent(smb2_close_request, vl);
		}

		return true;
	}

	bool SMB2_Close_Response::New(AnalyzerContext& context, Reader& reader)
	{
		flags = *reader.read<uint16>();
		reader.skip(4);
		creation_time = *reader.read<uint64>();
		last_access_time = *reader.read<uint64>();
		last_write_time = *reader.read<uint64>();
		change_time = *reader.read<uint64>();
		alloc_size = *reader.read<uint64>();
		eof = *reader.read<uint64>();
		file_attrs = *reader.read<uint32>();

		if (smb2_close_response) {
			auto vl = create_value_list(context);
			vl->append(new Val(flags, TYPE_COUNT));
			vl->append(new Val(TIMESTAMP(creation_time), TYPE_TIME));
			vl->append(new Val(TIMESTAMP(last_access_time), TYPE_TIME));
			vl->append(new Val(TIMESTAMP(last_write_time), TYPE_TIME));
			vl->append(new Val(TIMESTAMP(change_time), TYPE_TIME));
			vl->append(new Val(alloc_size, TYPE_COUNT));
			vl->append(new Val(eof, TYPE_COUNT));
			vl->append(new Val(file_attrs, TYPE_COUNT));

			context.QueueEvent(smb2_close_response, vl);
		}

		return true;
	}

	bool SMB2_Read_Request::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(1);
		flags = *reader.read<uint8>();
		length = *reader.read<uint32>();
		offset = *reader.read<uint64>();
		persistent_file_id = *reader.read<uint64>();
		volatile_file_id = *reader.read<uint64>();
		minimum_count = *reader.read<uint32>();
		channel = *reader.read<uint32>();
		remaining_bytes = *reader.read<uint32>();
		channel_info_offset = *reader.read<uint16>();
		channel_info_len = *reader.read<uint16>();

		if (channel_info_len > 0)
		{
			auto channel_info_buffer_offset = channel_info_offset - reader.current_pos + header->beginning;
			if (!reader.available(channel_info_buffer_offset + channel_info_len))
			{
				is_parsed = false;
				return false;
			}

			reader.skip(channel_info_buffer_offset);
			reader.skip(channel_info_len);
		} else {
			reader.skip(1);
		}

		if (smb2_read_request) {
			auto vl = create_value_list(context);
			vl->append(new Val(flags, TYPE_COUNT));
			vl->append(new Val(length, TYPE_COUNT));
			vl->append(new Val(offset, TYPE_COUNT));
			vl->append(new Val(minimum_count, TYPE_COUNT));
			vl->append(new Val(channel, TYPE_COUNT));
			vl->append(new Val(remaining_bytes, TYPE_COUNT));

			context.QueueEvent(smb2_read_request, vl);
		}

		return true;
	}

	bool SMB2_Read_Response::New(AnalyzerContext& context, Reader& reader)
	{
		data_offset = *reader.read<uint8>();
		reader.skip(1);
		data_len = *reader.read<uint32>();
		data_remaining = *reader.read<uint32>();
		reader.skip(4);

		auto req = request<SMB2_Read_Request>();
		if (req != nullptr)
		{
			volatile_file_id = req->volatile_file_id;
			offset = req->offset;
		}

		if (smb2_read_response) {
			auto vl = create_value_list(context);
			vl->append(new Val(data_len, TYPE_COUNT));
			vl->append(new Val(data_remaining, TYPE_COUNT));

			context.QueueEvent(smb2_read_response, vl);
		}
		return SMB2_FileMessage::New(context, reader);
	}

	bool SMB2_Write_Request::New(AnalyzerContext& context, Reader& reader)
	{
		data_offset = *reader.read<uint16>();
		data_len = *reader.read<uint32>();
		offset = *reader.read<uint64>();
		persistent_file_id = *reader.read<uint64>();
		volatile_file_id = *reader.read<uint64>();
		channel = *reader.read<uint32>();
		data_remaining = *reader.read<uint32>();
		channel_info_offset = *reader.read<uint16>();
		channel_info_len = *reader.read<uint16>();
		flags = *reader.read<uint32>();

		if (channel_info_len > 0)
		{
			auto channel_info_buffer_offset = channel_info_offset - reader.current_pos + header->beginning;
			if (!reader.available(channel_info_buffer_offset + channel_info_len))
			{
				is_parsed = false;
				return false;
			}

			reader.skip(channel_info_buffer_offset);
			reader.skip(channel_info_len);
		}

		if (smb2_write_request) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_write_request, vl);
		}

		return SMB2_FileMessage::New(context, reader);
	}

	bool SMB2_Write_Response::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(2);
		byte_count = *reader.read<uint32>();
		remaining = *reader.read<uint32>();
		channel_info_offset = *reader.read<uint16>();
		channel_info_len = *reader.read<uint16>();

		if (channel_info_len > 0)
		{
			auto channel_info_buffer_offset = channel_info_offset - reader.current_pos + header->beginning;
			if (!reader.available(channel_info_buffer_offset + channel_info_len))
			{
				is_parsed = false;
				return false;
			}

			reader.skip(channel_info_buffer_offset);
			reader.skip(channel_info_len);
		}

		if (smb2_write_response) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_write_response, vl);
		}

		return true;
	}

	bool SMB2_Cancel_Request::New(AnalyzerContext& context, Reader& reader)
	{
		reader.move_end();

		if (smb2_cancel_request) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_cancel_request, vl);
		}

		return true;
	}

	bool SMB2_Cancel_Response::New(AnalyzerContext& context, Reader& reader)
	{
		reader.move_end();

		if (smb2_cancel_response) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_cancel_response, vl);
		}

		return true;
	}

	bool SMB2_Query_Directory_Request::New(AnalyzerContext& context, Reader& reader)
	{
		info_class = *reader.read<uint8>();
		flags = *reader.read<uint8>();
		file_index = *reader.read<uint32>();
		persistent_file_id = *reader.read<uint64>();
		volatile_file_id = *reader.read<uint64>();
		filename_offset = *reader.read<uint16>();
		filename_len = *reader.read<uint16>();
		output_buffer_len = *reader.read<uint32>();

		if (filename_len > 0) {
			auto filename_buffer_offset = filename_offset - reader.current_pos + header->beginning;
			if (!reader.available(filename_buffer_offset + filename_len))
			{
				is_parsed = false;
				return false;
			}

			reader.skip(filename_buffer_offset);
			reader.skip(filename_len);
		}

		if (smb2_query_directory_request) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_query_directory_request, vl);
		}

		return true;
	}

	bool SMB2_Query_Directory_Response::New(AnalyzerContext& context, Reader& reader)
	{
		data_offset = *reader.read<uint16>();
		data_len = *reader.read<uint32>();

		return SMB2_Chunked_Body::New(context, reader);
	}

	void SMB2_Query_Directory_Response::Finished(AnalyzerContext& context, Reader& reader)
	{
		if (smb2_query_directory_response) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_query_directory_response, vl);
		}
	}

	void SMB2_Query_Directory_Response::ChunkReceived(AnalyzerContext& context, Reader& reader, uint32 length)
	{
		reader.skip(length);
	}

	bool SMB2_Flush_Request::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(6);
		persistent_file_id = *reader.read<uint64>();
		volatile_file_id = *reader.read<uint64>();

		if (smb2_flush_request) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_flush_request, vl);
		}

		return true;
	}

	bool SMB2_Flush_Response::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(2);

		if (smb2_flush_response) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_flush_response, vl);
		}

		return true;
	}

	bool SMB2_Lock_Request::New(AnalyzerContext& context, Reader& reader)
	{
		lock_count = *reader.read<uint16>();
		lock_sequence = *reader.read<uint32>();
		persistent_file_id = *reader.read<uint64>();
		volatile_file_id = *reader.read<uint64>();

		auto lock_size = lock_count * (8 + 8 + 4 + 4);
		if (!reader.available(lock_size))
		{
			is_parsed = false;
			return false;
		}

		reader.skip(lock_size);

		if (smb2_lock_request) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_lock_request, vl);
		}

		return true;
	}

	bool SMB2_Lock_Response::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(2);

		if (smb2_lock_response) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_lock_response, vl);
		}

		return true;
	}

	bool SMB2_Echo_Request::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(2);

		if (smb2_echo_request) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_echo_request, vl);
		}

		return true;
	}

	bool SMB2_Echo_Response::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(2);

		if (smb2_echo_response) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_echo_response, vl);
		}

		return true;
	}

	bool SMB2_Change_Notify_Request::New(AnalyzerContext& context, Reader& reader)
	{
		flags = *reader.read<uint16>();
		output_buffer_length = *reader.read<uint32>();
		persistent_file_id = *reader.read<uint64>();
		volatile_file_id = *reader.read<uint64>();
		completion_filter = *reader.read<uint32>();
		reader.skip(4);

		if (smb2_change_notify_request) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_change_notify_request, vl);
		}

		return true;
	}

	bool SMB2_Change_Notify_Response::New(AnalyzerContext& context, Reader& reader)
	{
		output_buffer_offset = *reader.read<uint16>();
		output_buffer_length = *reader.read<uint32>();

		if (output_buffer_length > 0) {
			auto buffer_offset = output_buffer_offset - reader.current_pos + header->beginning;
			if (!reader.available(buffer_offset + output_buffer_length))
			{
				is_parsed = false;
				return false;
			}

			reader.skip(buffer_offset);
			reader.skip(output_buffer_length);
		}

		if (smb2_change_notify_response) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_change_notify_response, vl);
		}

		return true;
	}

	bool SMB2_Query_Info_Request::New(AnalyzerContext& context, Reader& reader)
	{
		info_type = *reader.read<u_char>();
		file_info_class = *reader.read<u_char>();
		output_buffer_length = *reader.read<uint32>();
		input_buffer_offset = *reader.read<uint16>();
		reader.skip(2);
		input_buffer_length = *reader.read<uint32>();
		additional_information = *reader.read<uint32>();
		flags = *reader.read<uint32>();
		persistent_file_id = *reader.read<uint64>();
		volatile_file_id = *reader.read<uint64>();

		if (input_buffer_length > 0) {
			auto buffer_offset = input_buffer_offset - reader.current_pos + header->beginning;
			if (!reader.available(buffer_offset + input_buffer_length))
			{
				is_parsed = false;
				return false;
			}

			reader.skip(buffer_offset);
			reader.skip(input_buffer_length);
		}

		if (smb2_query_info_request) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_query_info_request, vl);
		}

		return true;
	}

	bool SMB2_Query_Info_Response::New(AnalyzerContext& context, Reader& reader)
	{
		output_buffer_offset = *reader.read<uint16>();
		output_buffer_length = *reader.read<uint32>();

		if (output_buffer_length > 0) {
			auto buffer_offset = output_buffer_offset - reader.current_pos + header->beginning;
			printf("size %u, %hu, %d\n", output_buffer_length, output_buffer_offset, buffer_offset);
			if (!reader.available(buffer_offset + output_buffer_length))
			{
				is_parsed = false;
				return false;
			}

			reader.skip(buffer_offset);
			reader.skip(output_buffer_length);
		}

		if (smb2_query_info_response) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_query_info_response, vl);
		}

		return true;
	}

	bool SMB2_Set_Info_Request::New(AnalyzerContext& context, Reader& reader)
	{
		info_type = *reader.read<u_char>();
		file_info_class = *reader.read<u_char>();
		buffer_length = *reader.read<uint32>();
		buffer_offset = *reader.read<uint16>();
		reader.skip(2);
		additional_information = *reader.read<uint32>();
		persistent_file_id = *reader.read<uint64>();
		volatile_file_id = *reader.read<uint64>();

		if (buffer_length > 0) {
			auto offset = buffer_offset - reader.current_pos + header->beginning;
			if (!reader.available(offset + buffer_length))
			{
				is_parsed = false;
				return false;
			}

			reader.skip(offset);
			reader.skip(buffer_length);
		}

		if (smb2_set_info_request) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_set_info_request, vl);
		}

		return true;
	}

	bool SMB2_Set_Info_Response::New(AnalyzerContext& context, Reader& reader)
	{
		if (smb2_set_info_response) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_set_info_response, vl);
		}

		return true;
	}

	bool SMB2_Ioctl_Request::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(2);
		ctl_code = *reader.read<uint32>();
		persistent_file_id = *reader.read<uint64>();
		volatile_file_id = *reader.read<uint64>();
		input_offset = *reader.read<uint32>();
		input_count = *reader.read<uint32>();
		max_input_response = *reader.read<uint32>();
		output_offset = *reader.read<uint32>();
		output_count = *reader.read<uint32>();
		max_output_response = *reader.read<uint32>();
		flags = *reader.read<uint32>();
		reader.skip(4);

		if (input_count > 0) {
			auto input_buffer_offset = input_offset - reader.current_pos + header->beginning;
			if (!reader.available(input_buffer_offset + input_count))
			{
				is_parsed = false;
				return false;
			}

			reader.skip(input_buffer_offset);
			reader.skip(input_count);
		}

		if (output_count > 0) {
			auto output_buffer_offset = output_offset - reader.current_pos + header->beginning;
			if (!reader.available(output_buffer_offset + output_count))
			{
				is_parsed = false;
				return false;
			}

			reader.skip(output_buffer_offset);
			reader.skip(output_count);
		}

		if (smb2_ioctl_request) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_ioctl_request, vl);
		}

		return true;
	}

	bool SMB2_Ioctl_Response::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(2);
		ctl_code = *reader.read<uint32>();
		persistent_file_id = *reader.read<uint64>();
		volatile_file_id = *reader.read<uint64>();
		input_offset = *reader.read<uint32>();
		input_count = *reader.read<uint32>();
		output_offset = *reader.read<uint32>();
		output_count = *reader.read<uint32>();
		flags = *reader.read<uint32>();
		reader.skip(4);

		if (input_count > 0) {
			auto input_buffer_offset = input_offset - reader.current_pos + header->beginning;
			if (!reader.available(input_buffer_offset + input_count))
			{
				is_parsed = false;
				return false;
			}

			reader.skip(input_buffer_offset);
			reader.skip(input_count);
		}

		if (output_count > 0) {
			auto output_buffer_offset = output_offset - reader.current_pos + header->beginning;
			if (!reader.available(output_buffer_offset + output_count))
			{
				is_parsed = false;
				return false;
			}

			reader.skip(output_buffer_offset);
			reader.skip(output_count);
		}

		if (smb2_ioctl_response) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_ioctl_response, vl);
		}

		return true;
	}

	bool SMB2_Oplock_Break_Request::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(header->structure_size-2);

		if (smb2_oplock_break_request) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_oplock_break_request, vl);
		}

		return true;
	}

	bool SMB2_Oplock_Break_Response::New(AnalyzerContext& context, Reader& reader)
	{
		reader.skip(header->structure_size-2);

		if (smb2_oplock_break_response) {
			auto vl = create_value_list(context);
			context.QueueEvent(smb2_oplock_break_response, vl);
		}

		return true;
	}
}
