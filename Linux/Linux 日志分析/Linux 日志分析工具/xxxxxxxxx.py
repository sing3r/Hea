import fnmatch
print(any(fnmatch.fnmatch("/media/sing/Elements/Sing3r/LogBackup/10.194.184.53/log/log/messages-20241208", p) for p in ['*auth.log*', '*secure*', '*messages*']))

