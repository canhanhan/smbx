#include <stdlib.h>
#include "Handler.h"
#include "Reporter.h"
#include "Event.h"
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
	
#define REGISTER_COMMAND(message,handler) \
	case message:\
		current_message = header->is_response ? (SMB2_Body*)new handler##_Response(analyzer, reader, header) : new handler##_Request(analyzer, reader, header); \
		break;
		
namespace SMBx 
{	
	enum SMB2_COMMAND
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
		SMB2_OPLOCK_BREAK       = 18,	
	};
	
	Handler::Handler(Analyzer* a, Reader* r) {
		is_last_finished = true;
		is_last_parsed = true;
		buffer = 0;
		buffer_len = 0;
		analyzer = a;	
		reader = r;
	}

	void Handler::handle(int len, const u_char* data)
	{
		reader->reset(len, data);
		
		//printf("Hebele1\n");
		do {
			//printf("Hebele2: cp: %u, l: %u\n", reader->current_pos, reader->len);
			uint16 beginning = reader->current_pos;
			
			if (is_last_finished == true) {				
				if (!is_last_parsed)
				{				
					printf("Continues: bl: %d, l: %d\n", buffer_len, len);					
					size_t size = len * sizeof(u_char);
					buffer = (u_char*)realloc(buffer, buffer_len*sizeof(u_char) + size);
					memcpy(&buffer[buffer_len], data, size);
					buffer_len = buffer_len + len;
					reader->reset(buffer_len, buffer);
				}
				
				is_last_parsed = handle_new();
				
				if (is_last_parsed) {				
					if (buffer != 0) {
						std::cout << "Free world" << std::endl;
						free(buffer);	
						buffer = 0;
						buffer_len = 0;
					}
				} else {
					printf("Needs to continue: b: %d, bl: %d, l: %d\n", beginning, buffer_len, len);
					uint16 previous_pos = buffer_len;
					buffer_len += len - beginning;					
					size_t buffer_size = buffer_len * sizeof(u_char);				
					buffer = (u_char*)malloc(buffer_size);
					memcpy(&buffer[previous_pos], &data[beginning], buffer_size);
					
					reader->move_end();
				}				
			} else {
				handle_continue();
			}
			
			if (is_last_finished == true && current_message != NULL) {
				delete current_message;
				current_message = NULL;
			}		
		} while (reader->current_pos < reader->len);
	}

	bool Handler::handle_new()
	{	
		// Find SMB2 magic
		while (reader->current_pos + 4 < reader->len && *((uint32*)(reader->data + reader->current_pos)) != 0x424D53FE)
		{
			reader->skip(1);
			if (reader->current_pos + 4 >= reader->len) {
				std::cout << "Not SMB2 package.\n";
				reader->move_end();
				return true;
			}
		}
		
		if (reader->len - reader->current_pos < 64) {
			return false;
		}
		
		reader->skip(4);		
		SMB2_Header* header = new SMB2_Header(analyzer, reader, reader->current_pos - 4);	
		header->New();
		
		if (header->is_response && header->status != STATUS_SUCCESS
			&& !(header->command == SMB2_SESSION_SETUP && header->status == STATUS_MORE_PROCESSING_REQUIRED)
			//&& !(header->command == SMB2_QUERY_DIRECTORY && header->status == STATUS_NO_MORE_FILES)
			&& !(header->command == SMB2_QUERY_INFO && header->status == STATUS_BUFFER_OVERFLOW)
			&& !(header->command == SMB2_READ && header->status == STATUS_BUFFER_OVERFLOW)
			&& !(header->command == SMB2_IOCTL && header->status == STATUS_BUFFER_OVERFLOW)
			&& !(header->command == SMB2_READ && header->status == STATUS_INVALID_PARAMETER)
			&& !(header->command == SMB2_READ && header->status == STATUS_NOTIFY_ENUM_DIR))
		{
			current_message = new SMB2_Error(analyzer, reader, header);
		} else {			
			switch (header->command)
			{
				REGISTER_COMMAND(SMB2_NEGOTIATE_PROTOCOL,SMB2_Negotiate);
				REGISTER_COMMAND(SMB2_SESSION_SETUP, SMB2_Session_Setup);
				REGISTER_COMMAND(SMB2_LOGOFF, SMB2_Logoff);
				REGISTER_COMMAND(SMB2_TREE_CONNECT, SMB2_Tree_Connect);
				REGISTER_COMMAND(SMB2_TREE_DISCONNECT, SMB2_Tree_Disconnect);
				REGISTER_COMMAND(SMB2_CREATE, SMB2_Create);
				REGISTER_COMMAND(SMB2_CLOSE, SMB2_Close);
				// REGISTER_COMMAND(SMB2_FLUSH, SMB2_Flush);
				REGISTER_COMMAND(SMB2_READ, SMB2_Read);
				REGISTER_COMMAND(SMB2_WRITE, SMB2_Write);
				// REGISTER_COMMAND(SMB2_LOCK, SMB2_Lock);
				// REGISTER_COMMAND(SMB2_IOCTL, SMB2_Ioctl);
				REGISTER_COMMAND(SMB2_CANCEL, SMB2_Cancel);
				// REGISTER_COMMAND(SMB2_ECHO, SMB2_Echo);
				REGISTER_COMMAND(SMB2_QUERY_DIRECTORY, SMB2_Query_Directory);
				// REGISTER_COMMAND(SMB2_CHANGE_NOTIFY, SMB2_Change_Notify);
				// REGISTER_COMMAND(SMB2_QUERY_INFO, SMB2_Query_Info);
				// REGISTER_COMMAND(SMB2_SET_INFO, SMB2_Set_Info);
				// REGISTER_COMMAND(SMB2_OPLOCK_BREAK, SMB2_Oplock_Break);	
				default:
					printf("Unknown command: %hu\n", header->command);
					reader->move_end();
					delete header;
					return true;
			}		
		}
		
		uint16 avail = reader->len - reader->current_pos;
		//printf("Size: %hu, mid: %u, isr: %d, Command: %hu, Status: 0x%X, ss: %u, av: %u, CMD: %u, MSG:%lu, TID: %u, SID: 0x%lX\n", header->header_size, header->messageId, header->is_response, header->command, header->status, header->structure_size, avail, header->next_command, header->messageId, header->treeId, header->sessionId);
			
		if (header->structure_size - 2 > avail)
		{
			return false;
		} else {
			is_last_finished = current_message->New();				
			return true;
		}
	}

	void Handler::handle_continue()
	{
		if (current_message == NULL) {
			printf("current_message was NULL!\n");
			throw "current_message was NULL!";
		}
		
		is_last_finished = current_message->Continue();	
	}
}