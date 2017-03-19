@load policy/protocols/smb
@load policy/protocols/ssl/validate-certs.bro 


#Define new record type "MyRec" to hold {String, # Of Hits}
type MyRec: record {
    s: string;
    c: count;};



#Define a new Vector type "MyVec"
type MyVec: vector of MyRec;

#Vectors to hold connection related stats that do not require counting
global bytes_uploaded: vector of MyRec;
global bytes_downloaded: vector of MyRec;
global conn_duration: vector of MyRec;


global t_conn_fields: table[string] of vector of string = 
{
["Listening_TCP_Ports_on_Private_IPs"] = vector(),
["Listening_TCP_Ports_on_Public_IPs"] = vector(),
};

global t_http_fields: table[string] of vector of string = 
{
["Odd_Hosts"] = vector(),
["Methods"] = vector(),
["Referrers"] = vector(),
["Response_Codes"] = vector(),
["User-Agents"] = vector(),
["Client_Requests"] = vector(),
};

global t_dns_fields: table[string] of vector of string = 
{
["Client_Queries"] = vector(),
["Query_Types"] = vector(),
#["TTLs"] = vector(),
["NXDOMAIN_Queries"] = vector(),
["Odd_Queries"] = vector(),
};


global t_smb1_fields: table[string] of vector of string = 
{
["File_Actions"] = vector(),
["File_Names"] = vector(),
["Domains"] = vector(),
["Usernames"] = vector(),
["Hostnames"] = vector(),
["Sessions"] = vector(),
};

global t_smb2_fields: table[string] of vector of string = 
{
["File_Actions"] = vector(),
["File_Names"] = vector(),
["Domains"] = vector(),
["Usernames"] = vector(),
["Hostnames"] = vector(),
["Sessions"] = vector(),
};

global t_ssh_fields: table[string] of vector of string = 
{
["Client_Strings"] = vector(),
["Server_Strings"] = vector(),
["Auth_Success"] = vector(),
["Sessions"] = vector(),
};

global t_ssl_fields: table[string] of vector of string = 
{
["Issuers"] = vector(),
["Validation_Status"] = vector(),
["Servers_Names"] = vector(),
};

global t_rdp_fields: table[string] of vector of string = 
{
["Sessions"] = vector(),
["Usernames"] = vector(),
};

global t_irc_fields: table[string] of vector of string = 
{
["session"] = vector(),
["username"] = vector(),
["nick"] = vector(),
};

global t_ftp_fields: table[string] of vector of string = 
{
["Usernames"] = vector(),
["Commands"] = vector(),
["Current_Working_Directories"] = vector(),
["Sessions"] = vector(),
};

global t_identified_files: table[string] of vector of string = 
{
["MIME_Types"] = vector(),
};


#Supportive function "MyFunc_Ascending" to be used by "sort" function
function MyFunc_Ascending(a: MyRec, b: MyRec): int
	{
	if (a$c < b$c)
		return -1;
	else
		return 1;
	}


#Supportive function "MyFunc_Descending" to be used by "sort" function
function MyFunc_Descending(a: MyRec, b: MyRec): int
	{
	if (a$c < b$c)
		return 1;
	else
		return -1;
	}

function count_hits(v: vector of string): table[string] of count
	{
	local t: table[string] of count;
	for (i in v)
		if (v[i] !in t)
			t[v[i]] = 1;
		else
			++t[v[i]];
	return (t);
	}

function table_to_vector(t:table[string] of count): MyVec
	{
	local v: MyVec;
	for (k in t)
		v[|v|] = [$s=k,$c=t[k]];
	return (v);	
	}


function print_table(v: MyVec,field: string)
	{
	print fmt(" ");
	print fmt(" ");
	print fmt(" ");
	print "==========================================================";
	print field;
	print "==========================================================";
	print fmt(" ");
	for (i in v)
		print fmt("%-7d          %s",v[i]$c,v[i]$s);
	}



function print_vector(v: MyVec,field: string)
	{
	print fmt(" ");
	print fmt(" ");
	print fmt(" ");
	print "==========================================================";
	print field;
	print "==========================================================";
	print fmt(" ");
	for (i in v)
		print fmt("%-12d          %s",v[i]$c,v[i]$s);
	}




event Conn::log_conn(rec: Conn::Info)
{
	if (rec$resp_pkts > 10)
	{
	
		if (rec?$history && "h" in rec$history)
		{

			if ( $c=rec$orig_bytes > 1000000)
				bytes_uploaded[|bytes_uploaded|] =  [$s=fmt("%-16s %s %-16s %s %s",rec$id$orig_h,"------->",rec$id$resp_h,":",rec$id$resp_p) ,$c=rec$orig_bytes];
	
			if ( $c=rec$resp_bytes > 3000000)
				bytes_downloaded[|bytes_downloaded|] = [$s=fmt("%-16s %s  %-16s %s %s",rec$id$orig_h,"<-------",rec$id$resp_h,":",rec$id$resp_p) ,$c=rec$resp_bytes];

			if ($c=(double_to_count(interval_to_double(rec$duration)) > 600))
				conn_duration[|conn_duration|] = [$s=fmt("%-16s %s     %-16s %s %s",rec$id$orig_h,"<------->",rec$id$resp_h,":",rec$id$resp_p) ,$c=(double_to_count(interval_to_double(rec$duration)))];
		
			if (rec?$service)
				if (Site::is_private_addr(rec$id$resp_h))
					t_conn_fields["Listening_TCP_Ports_on_Private_IPs"][|t_conn_fields["Listening_TCP_Ports_on_Private_IPs"]|] = fmt("%-9s %s %-16s %s",rec$id$resp_p,"listening on ",rec$id$resp_h, rec$service);
				else
					t_conn_fields["Listening_TCP_Ports_on_Public_IPs"][|t_conn_fields["Listening_TCP_Ports_on_Public_IPs"]|] = fmt("%-9s %s %s",rec$id$resp_p,"------->",rec$service);	
			else
					if (Site::is_private_addr(rec$id$resp_h))
						t_conn_fields["Listening_TCP_Ports_on_Private_IPs"][|t_conn_fields["Listening_TCP_Ports_on_Private_IPs"]|] = fmt("%-9s %s %-16s %s",rec$id$resp_p,"listening on ",rec$id$resp_h, "-");
					else
						t_conn_fields["Listening_TCP_Ports_on_Public_IPs"][|t_conn_fields["Listening_TCP_Ports_on_Public_IPs"]|] = fmt("%-9s %s %s",rec$id$resp_p,"------->","-");	
		}
	}
}


event HTTP::log_http(rec: HTTP::Info)
{
	if (rec?$host && rec?$status_code)
		{
		if ((find_last(rec$host, /\.[a-z]+$/) !in set(".com",".net",".org")) || (|rec$host| > 30)) 
			t_http_fields["Odd_Hosts"][|t_http_fields["Odd_Hosts"]|] = cat(rec$host);
	

		if (rec?$referrer)
 			t_http_fields["Referrers"][|t_http_fields["Referrers"]|] = split_string(rec$referrer,/\//)[2];
		else
			t_http_fields["Referrers"][|t_http_fields["Referrers"]|] = "-";

		if (rec?$user_agent)
 			t_http_fields["User-Agents"][|t_http_fields["User-Agents"]|] = cat(rec$user_agent);
		else
			t_http_fields["User-Agents"][|t_http_fields["User-Agents"]|] = "-";
	
		t_http_fields["Methods"][|t_http_fields["Methods"]|] = cat(rec$method);
		t_http_fields["Client_Requests"][|t_http_fields["Client_Requests"]|] = cat(rec$id$orig_h);
		t_http_fields["Response_Codes"][|t_http_fields["Response_Codes"]|] = cat(rec$status_code);
		}
}




event DNS::log_dns(rec: DNS::Info)
{
	if (rec?$qtype_name && rec?$rcode)
	{
		if (rec$rcode == 3)
			t_dns_fields["NXDOMAIN_Queries"][|t_dns_fields["NXDOMAIN_Queries"]|] = cat(rec$id$orig_h);

		if (rec$rcode == 0 && rec$qtype_name != "NBSTAT")
		{
			t_dns_fields["Client_Queries"][|t_dns_fields["Client_Queries"]|] = cat(rec$id$orig_h);
			t_dns_fields["Query_Types"][|t_dns_fields["Query_Types"]|] = cat(rec$qtype_name);			
			
#			if ((|rec$query| > 30) || (find_last(rec$query, /\.[a-z]+$/) !in set(".com",".net",".org")) || (|split_string(rec$query,/\./)|  > 6))
			if ((|rec$query| > 30) || (find_last(rec$query, /\.[a-z]+$/) !in set(".com",".net",".org")))
				t_dns_fields["Odd_Queries"][|t_dns_fields["Odd_Queries"]|] = cat(rec$query);
			
# The TTL check below was aimed at catching single flux behaviour, however, its very noisy (probably will be deleted) since almost all CDN traffic have dns answers with TTL < 30 seconds.
#			if (rec?$TTLs)
#				for (i in rec$TTLs)
#					if (double_to_count(interval_to_double(rec$TTLs[i])) < 150)
#		 				t_dns_fields["TTLs"][|t_dns_fields["TTLs"]|] = fmt("%-20s %s %s",rec$TTLs[i]," ---------> ",rec$answers[i]);
		}
	}
}


event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool)
{
if (c?$ntlm && c$smb_state?$current_file && c$smb_state$current_file?$name && (c$smb_state$current_tree$share_type == "DISK") && (c$ntlm?$status && c$ntlm$status == "SUCCESS"))
	{
	t_smb1_fields["Sessions"][|t_smb1_fields["Sessions"]|] = fmt("%-16s %s %-16s %s  %s",c$id$orig_h,"------->",c$id$resp_h,":",c$id$resp_p);
 	t_smb1_fields["File_Actions"][|t_smb1_fields["File_Actions"]|] = cat(c$smb_state$current_file$action);
	t_smb1_fields["File_Names"][|t_smb1_fields["File_Names"]|] = cat(c$smb_state$current_file$name);
	if (c$ntlm?$domainname)
		t_smb1_fields["Domains"][|t_smb1_fields["Domains"]|] = cat(c$ntlm$domainname);
	if (c$ntlm?$username)
		t_smb1_fields["Usernames"][|t_smb1_fields["Usernames"]|] = cat(c$ntlm$username);
	if(c$ntlm?$hostname)	
		t_smb1_fields["Hostnames"][|t_smb1_fields["Hostnames"]|] = cat(c$ntlm$hostname);
	}	
}




event smb2_message(c: connection, hdr: SMB2::Header, is_orig: bool)
{
if (c?$ntlm && c$smb_state?$current_file && c$smb_state$current_file?$name && (c$smb_state$current_tree$share_type == "DISK") && c$ntlm$status == "SUCCESS")
	{
	t_smb2_fields["Sessions"][|t_smb2_fields["Sessions"]|] = fmt("%-16s %s %-16s %s  %s",c$id$orig_h,"------->",c$id$resp_h,":",c$id$resp_p);
 	t_smb2_fields["File_Actions"][|t_smb2_fields["File_Actions"]|] = cat(c$smb_state$current_file$action);
	t_smb2_fields["File_Names"][|t_smb2_fields["File_Names"]|] = cat(c$smb_state$current_file$name);
	
	if (c$ntlm?$domainname && c$ntlm?$username)
		t_smb2_fields["Usernames"][|t_smb2_fields["Usernames"]|] = fmt("%-20s %-10s %s",c$ntlm$domainname,"\\",c$ntlm$username );
	else	
		t_smb2_fields["Usernames"][|t_smb2_fields["Usernames"]|] = fmt("%-20s",c$ntlm$username );
	if(c$ntlm?$hostname)	
		t_smb2_fields["Hostnames"][|t_smb2_fields["Hostnames"]|] = cat(c$ntlm$hostname);		
	}
}


event SSH::log_ssh(rec: SSH::Info)
{
	if (rec?$server)
		{
		t_ssh_fields["Sessions"][|t_ssh_fields["Sessions"]|] = fmt("%-16s %s %-16s %s %s",rec$id$orig_h,"------->",rec$id$resp_h,":",rec$id$resp_p);
		t_ssh_fields["Server_Strings"][|t_ssh_fields["Server_Strings"]|] = cat(rec$server);
		if (rec?$client)
			t_ssh_fields["Client_Strings"][|t_ssh_fields["Client_Strings"]|] = cat(rec$client);
		if (rec?$auth_success)
			t_ssh_fields["Auth_Success"][|t_ssh_fields["Auth_Success"]|] = cat(rec$auth_success);
		}
}


event SSL::log_ssl(rec: SSL::Info)
{
	if (rec?$issuer)
		{
#		t_ssl_fields["Issuers"][|t_ssl_fields["Issuers"]|] = cat(rec$issuer);
#		t_ssl_fields["Issuers"][|t_ssl_fields["Issuers"]|] = split_string(rec$issuer,/,/);
		for (f in (split_string(rec$issuer,/,/)))
			if (/CN=/ in (split_string(rec$issuer,/,/))[f])
				{
				t_ssl_fields["Issuers"][|t_ssl_fields["Issuers"]|] = (split_string(rec$issuer,/,/))[f];
				break;
				}
		t_ssl_fields["Validation_Status"][|t_ssl_fields["Validation_Status"]|] = cat(rec$validation_status);	
		if (rec?$server_name)
#			t_ssl_fields["Servers_Names"][|t_ssl_fields["Servers_Names"]|] = cat(rec$server_name);
			t_ssl_fields["Servers_Names"][|t_ssl_fields["Servers_Names"]|] = find_last(rec$server_name,/\..+\..+/);
		}
}


event RDP::log_rdp(rec: RDP::Info)
{
	t_rdp_fields["Sessions"][|t_rdp_fields["Sessions"]|] = fmt("%-16s %s %-16s %s %s",rec$id$orig_h,"------->",rec$id$resp_h,":",rec$id$resp_p);
	t_rdp_fields["Usernames"][|t_rdp_fields["Usernames"]|] = cat(rec$cookie);
}


event IRC::irc_log(rec: IRC::Info)
{
	t_irc_fields["session"][|t_irc_fields["session"]|] = fmt("%-16s %s %-16s %s %s",rec$id$orig_h,"------->",rec$id$resp_h,":",rec$id$resp_p);
	t_irc_fields["username"][|t_irc_fields["username"]|] = cat(rec$user);
	if (rec?$nick)	
		t_irc_fields["nick"][|t_irc_fields["nick"]|] = cat(rec$nick);
}



event FTP::log_ftp(rec: FTP::Info)
{

	t_ftp_fields["Commands"][|t_ftp_fields["Commands"]|] = cat(rec$command);
	t_ftp_fields["Current_Working_Directories"][|t_ftp_fields["Current_Working_Directories"]|] = cat(rec$cwd);
	t_ftp_fields["Sessions"][|t_ftp_fields["Sessions"]|] = fmt("%-16s %s %-16s %s %s",rec$id$orig_h,"------->",rec$id$resp_h,":",rec$id$resp_p);
	if (rec?$user)
		t_ftp_fields["Usernames"][|t_ftp_fields["Usernames"]|] = cat(rec$user);

}


event Files::log_files(rec: Files::Info)
{

if (rec?$mime_type)
	t_identified_files["MIME_Types"][|t_identified_files["MIME_Types"]|] = fmt("%-40s %s %s",rec$mime_type,"------->",rec$source);
}


event bro_done()
{
#Printing values counted and sorted
for (k in t_http_fields)
		if (|t_http_fields[k]| != 0)
			print_table(sort(table_to_vector(count_hits(t_http_fields[k])),MyFunc_Ascending),"HTTP "+cat(k));

for (k in t_dns_fields)
	if (|t_dns_fields[k]| != 0)	
		print_table(sort(table_to_vector(count_hits(t_dns_fields[k])),MyFunc_Ascending),"DNS "+cat(k));

for (k in t_smb2_fields)
	if (|t_smb2_fields[k]| != 0)	
		print_table(sort(table_to_vector(count_hits(t_smb2_fields[k])),MyFunc_Ascending),"SMB2 "+cat(k));

for (k in t_ssh_fields)
	if (|t_ssh_fields[k]| != 0)	
		print_table(sort(table_to_vector(count_hits(t_ssh_fields[k])),MyFunc_Ascending),"SSH "+cat(k));


for (k in t_ftp_fields)
	if (|t_ftp_fields[k]| != 0)	
		print_table(sort(table_to_vector(count_hits(t_ftp_fields[k])),MyFunc_Ascending),"FTP "+cat(k));

for (k in t_ssl_fields)
	if (|t_ssl_fields[k]| != 0)	
		print_table(sort(table_to_vector(count_hits(t_ssl_fields[k])),MyFunc_Ascending),"SSL "+cat(k));

for (k in t_rdp_fields)
	if (|t_rdp_fields[k]| != 0)	
		print_table(sort(table_to_vector(count_hits(t_rdp_fields[k])),MyFunc_Ascending),"RDP "+cat(k));

for (k in t_irc_fields)
	if (|t_irc_fields[k]| != 0)	
		print_table(sort(table_to_vector(count_hits(t_irc_fields[k])),MyFunc_Ascending),"IRC "+cat(k));

for (k in t_conn_fields)
	if (|t_conn_fields[k]| != 0)	
		print_table(sort(table_to_vector(count_hits(t_conn_fields[k])),MyFunc_Ascending),"Conn "+cat(k));


for (k in t_identified_files)
	if (|t_identified_files[k]| != 0)	
		print_table(sort(table_to_vector(count_hits(t_identified_files[k])),MyFunc_Ascending),"File "+cat(k));


if (|sort(bytes_uploaded,MyFunc_Descending)| !=0 )
	print_vector(sort(bytes_uploaded,MyFunc_Descending),"Bytes Uploaded > {1000000 Bytes / 1 MB}");

if (|sort(bytes_downloaded,MyFunc_Descending)| !=0 )
	print_vector(sort(bytes_downloaded,MyFunc_Descending),"Bytes Downloaded > {3000000 Bytes / 3 MB}");

if (|sort(conn_duration,MyFunc_Descending)| !=0 )
	print_vector(sort(conn_duration,MyFunc_Descending),"Conn Duration > {600 Second / 10 Minutes}");

}
