#include <stdlib.h>
#include <memory>
#include "Reporter.h"
#include "Event.h"
#include "Handler.h"
#include "Message.h"

#define STATUS_SUCCESS						0x00000000
#define STATUS_LOGON_FAILURE				0xC000006D
#define STATUS_BAD_NETWORK_NAME				0xC00000CC
#define STATUS_ACCESS_DENIED				0xC0000022
#define STATUS_MORE_PROCESSING_REQUIRED		0xC0000016
#define STATUS_USER_SESSION_DELETED			0xC0000203
#define STATUS_INVALID_PARAMETER			0xC000000D
#define STATUS_FS_DRIVER_REQUIRED			0xC000019C
#define STATUS_NOT_SUPPORTED				0xC00000BB
#define STATUS_NETWORK_NAME_DELETED			0xC00000C9
#define STATUS_FILE_CLOSED					0xC0000128
#define STATUS_OBJECT_NAME_NOT_FOUND		0xC0000034
#define STATUS_NO_MORE_FILES				0x80000006
#define STATUS_BUFFER_OVERFLOW				0x80000005
#define STATUS_NO_MORE_FILES				0x80000006
#define STATUS_NOTIFY_ENUM_DIR				0x0000010C

#define SMBX_COMMAND(handlerType) \
	CommandPair( \
		[] (shared_ptr<SMB2_Header> header) -> shared_ptr<SMB2_Body> { return make_shared<handlerType##_Request>(header); }, \
		[] (shared_ptr<SMB2_Header> header, shared_ptr<SMB2_Body> request) -> shared_ptr<SMB2_Body> { return make_shared<handlerType##_Response>(header, request); } \
	)

namespace SMBx
{
	enum SMB2_COMMAND : uint16
	{
		SMB2_NEGOTIATE_PROTOCOL = 0,
		SMB2_SESSION_SETUP      = 1,
		SMB2_LOGOFF             = 2,
		SMB2_TREE_CONNECT       = 3,
		SMB2_TREE_DISCONNECT    = 4,
		SMB2_CREATE             = 5,
		SMB2_CLOSE              = 6,
		SMB2_FLUSH              = 7,
		SMB2_READ               = 8,
		SMB2_WRITE              = 9,
		SMB2_LOCK               = 10,
		SMB2_IOCTL              = 11,
		SMB2_CANCEL             = 12,
		SMB2_ECHO               = 13,
		SMB2_QUERY_DIRECTORY    = 14,
		SMB2_CHANGE_NOTIFY      = 15,
		SMB2_QUERY_INFO         = 16,
		SMB2_SET_INFO           = 17,
		SMB2_OPLOCK_BREAK       = 18
	};

	Commands::Commands()
	{
		commands[SMB2_NEGOTIATE_PROTOCOL] = SMBX_COMMAND(SMB2_Negotiate);
		commands[SMB2_SESSION_SETUP] = SMBX_COMMAND(SMB2_Session_Setup);
		commands[SMB2_LOGOFF] = SMBX_COMMAND(SMB2_Logoff);
		commands[SMB2_TREE_CONNECT] = SMBX_COMMAND(SMB2_Tree_Connect);
		commands[SMB2_TREE_DISCONNECT] = SMBX_COMMAND(SMB2_Tree_Disconnect);
		commands[SMB2_CREATE] = SMBX_COMMAND(SMB2_Create);
		commands[SMB2_CLOSE] = SMBX_COMMAND(SMB2_Close);
		commands[SMB2_FLUSH] = SMBX_COMMAND(SMB2_Flush);
		commands[SMB2_READ] = SMBX_COMMAND(SMB2_Read);
		commands[SMB2_WRITE] = SMBX_COMMAND(SMB2_Write);
		commands[SMB2_LOCK] = SMBX_COMMAND(SMB2_Lock);
		commands[SMB2_IOCTL] = SMBX_COMMAND(SMB2_Ioctl);
		commands[SMB2_CANCEL] = SMBX_COMMAND(SMB2_Cancel);
		commands[SMB2_ECHO] = SMBX_COMMAND(SMB2_Echo);
		commands[SMB2_QUERY_DIRECTORY] = SMBX_COMMAND(SMB2_Query_Directory);
		commands[SMB2_CHANGE_NOTIFY] = SMBX_COMMAND(SMB2_Change_Notify);
		commands[SMB2_QUERY_INFO] = SMBX_COMMAND(SMB2_Query_Info);
		commands[SMB2_SET_INFO] = SMBX_COMMAND(SMB2_Set_Info);
		commands[SMB2_OPLOCK_BREAK] = SMBX_COMMAND(SMB2_Oplock_Break);
	}

	const CommandPair Commands::get(uint16 command, bool is_response) const
	{
		auto it = commands.find(command);
		if (it == commands.end())
			return default_command;

		return it->second;
	}

	void Handler::handle(int len, const u_char* data)
	{
		reader.reset(len, data);

		do {
			if (is_last_finished) {
				auto beginning = reader.current_pos;

				if (!is_last_parsed) {
					buffer.append(len, data);
					reader.reset(buffer.len(), buffer.data());
				}

				is_last_parsed = handle_new();
				DEBUG_MSG("Handle: %s, Parsed: %s\n", is_last_parsed ? "Parsed" : "Not parsed", is_last_finished ? "Finished" : "Incomplete");

				if (!is_last_parsed) {
					buffer.append(reader.len - beginning, reader.data + beginning);
					break;
				}
			} else {
				handle_continue();
			}

			if (is_last_finished == true && current_message != nullptr && current_message->header->is_response) {
				DEBUG_MSG("Deleting message...\n");
				current_message = nullptr;
			}

		} while (reader.available(1));

		if (is_last_parsed)
			buffer.reset();
	}

	bool first_message = true;
	bool Handler::handle_new()
	{
		// Find SMB2 magic
		do {
			if (!reader.available(4))
				return false;

			reader.skip(1);			
		} while (*((uint32*)(reader.data + reader.current_pos)) != 0x424D53FE);

		// 64 bytes for header and 2 bytes for structure size
		if (!reader.available(66)) {
			DEBUG_MSG("Buffer is too small for header\n");
			return false;
		}

		auto header = make_shared<SMB2_Header>();
		header->New(reader);
		DEBUG_MSG("Header parsed: cmd:%hx id:%lu  fl:%hhx\n", header->command, header->messageId, header->flags);
		current_message = get_message(header);

		if (current_message == nullptr)
		{
			DEBUG_MSG("Unknown command: %hu\n", header->command);
			return true;
		}

		if (!reader.available(header->structure_size - 2)) // Structure is not part of header - hence the - 2
		{
			DEBUG_MSG("Buffer is too small for packet structure\n");
			return false;
		} else {
			bool result = current_message->New(context, reader);
			if (!result) {
				// if result is false; either the packet was too small to be parsed; or it had chunked body
				is_last_finished = !current_message->is_parsed;
				if (!current_message->is_parsed) {
					DEBUG_MSG("Buffer is too small for packet\n");
					current_message = nullptr;
					return false;
				}
			}

			if (!header->is_response)
				context.state.PushMessage(header->messageId, current_message);

			return true;
		}
	}

	void Handler::handle_continue()
	{
		ASSERT(current_message != nullptr);
		DEBUG_MSG("Continue...\n");
		is_last_finished = current_message->Continue(context, reader);
	}

	shared_ptr<SMB2_Body> Handler::get_message(shared_ptr<SMB2_Header> header)
	{
		auto command_id = header->command;
		auto status = header->status;
		auto is_response = header->is_response;
		shared_ptr<SMB2_Body> request;

		if (is_response)
			request = context.state.PopMessage(header->messageId);

		if (is_response && status != STATUS_SUCCESS
			&& !(command_id == SMB2_SESSION_SETUP && status == STATUS_MORE_PROCESSING_REQUIRED)
			&& !(command_id == SMB2_QUERY_INFO && status == STATUS_BUFFER_OVERFLOW)
			&& !(command_id == SMB2_READ && status == STATUS_BUFFER_OVERFLOW)
			&& !(command_id == SMB2_IOCTL && status == STATUS_BUFFER_OVERFLOW)
			&& !(command_id == SMB2_READ && status == STATUS_INVALID_PARAMETER)
			&& !(command_id == SMB2_READ && status == STATUS_NOTIFY_ENUM_DIR))
		{
			return make_shared<SMB2_Error>(header, request);
		}

		auto pair = commands.get(command_id, is_response);
		return is_response ? pair.response(header, request) : pair.request(header);
	}
}
