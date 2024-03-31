# ClassicalDLLInjects

Usage: .\ClassicalDLLInjects.exe <PID> [Full PathOfDll here]

It's meant to be a classical DLL injector. Inject into your process of choice, then press enter. The DLL Injector itself is nothing special, however, this was meant to be an exercise on creating a custom GetProcAddress via parsing a DLL's export address table. This stops GetProcAddress from showing up on the program's imports, thus hopefully making it more stealthy. 

