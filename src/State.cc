#include <memory>
#include "file_analysis/Manager.h"
#include "State.h"

namespace SMBx 
{
	SMB2_File::SMB2_File(uint64 id, string tree_name, string local_path) : id(id), tree_name(tree_name) 
	{
		path = tree_name + "\\" + local_path;

		size_t i = local_path.rfind('\\', local_path.length());
		name = (i != string::npos) ? local_path.substr(i+1, local_path.length() - i) : "<unknown>";

		file_id = file_mgr->HashHandle(path);
	};	
	
	SMB2_File::~SMB2_File() 
	{
		file_mgr->EndOfFile(file_id);
	};	
	
	shared_ptr<SMB2_Session> State::GetSession(uint64 session_id)
	{
		auto it = sessions.find(session_id);
		if (it == sessions.end()) {
			NewSession(session_id);
			return GetSession(session_id);	
		}
		
		return it->second;
	}
	
	string State::GetTreeConnection(uint64 session_id, uint32 tree_id)
	{
		auto session = GetSession(session_id);
		
		auto it = session->tree_connections.find(tree_id);
		if (it == session->tree_connections.end())
			return string("\\\\<unknown>");			
		
		return it->second;
	}
	
	shared_ptr<SMB2_File> State::GetFile(uint64 session_id, uint32 tree_id, uint64 file_id)
	{
		auto session = GetSession(session_id);
		
		auto it = session->files.find(file_id);
		if (it == session->files.end())
			return nullptr;	
						
		return it->second;
	}
	
	void State::NewSession(uint64 id)
	{
		sessions[id] = make_shared<SMB2_Session>(id);
		
		DEBUG_MSG("New session: sid: %lu\n", id);
	}
	
	void State::NewTreeConnection(uint64 session_id, uint32 tree_id, string name)
	{
		auto session = GetSession(session_id);
			
		session->tree_connections[tree_id] = name;
		
		DEBUG_MSG("New tree: sid: %lu, tid: %u, name: %s\n", session_id, tree_id, name.c_str());
	}	
	
	void State::NewFile(uint64 session_id, uint32 tree_id, uint64 file_id, string name)
	{
		auto session = GetSession(session_id);
				
		auto tree = GetTreeConnection(session_id, tree_id);		
		session->files[file_id] = make_shared<SMB2_File>(file_id, tree, name);
		
		DEBUG_MSG("New file: sid: %lu, tid: %u, fid: %lu, tree: %s, name: %s\n", session_id, tree_id, file_id, tree.c_str(), name.c_str());
	}	
	
	void State::CloseFile(uint64 session_id, uint32 tree_id, uint64 file_id)
	{
		auto session = GetSession(session_id);
				
		session->files.erase(file_id);	
		
		DEBUG_MSG("Close file: sid: %lu, tid: %u, fid: %lu\n", session_id, tree_id, file_id);
	}		
	
	void State::CloseTreeConnection(uint64 session_id, uint32 tree_id)
	{
		auto session = GetSession(session_id);
		
		session->tree_connections.erase(tree_id);

		DEBUG_MSG("Close tree: sid: %lu, tid: %u\n", session_id, tree_id);
	}
	
	void State::CloseSession(uint64 id)
	{
		sessions.erase(id);
		
		DEBUG_MSG("Close session: sid: %lu\n", id);
	}	
	
	void State::PushMessage(uint64 message_id, shared_ptr<SMB2_Body> message)
	{
		states[message_id] = message;
	}
	
	shared_ptr<SMB2_Body> State::PopMessage(uint64 message_id)
	{
		auto it = states.find(message_id);
		if (it == states.end())
			return nullptr;			
		
		return it->second;
	}
}