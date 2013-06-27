// http://floodyberry.wordpress.com/2008/09/08/generating-dll-wrappers

#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <direct.h>
#include <stdio.h>
#include <string.h>

#define UNMANGLE

#if defined(UNMANGLE)
	#include "Dbghelp.h"
	#pragma comment(lib, "Dbghelp.lib")
#endif

typedef BYTE u8;
typedef WORD u16;
typedef DWORD u32;

/*
	Simple rotating format buffer, nbuffers must be a power of 2
*/

template< u32 nbuffers, u32 nbytes >
struct fmtbuffers {
	fmtbuffers() : mBuffer(0) {}
	char *getbuffer() { return mBuffers[ mBuffer++ & ( nbuffers - 1 ) ]; }
	u32 getbuffersize() const { return nbytes; }
	const char *operator() ( const char *fmt, ... ) {
		char *buf = getbuffer();

		va_list args;
		va_start( args, fmt );
		buf[_vsnprintf( buf, nbytes - 1, fmt, args )] = NULL;
		va_end( args );

		return( buf );
	}
protected:
	char mBuffers[nbuffers][nbytes];
	u32 mBuffer;
};

fmtbuffers<64,256> fmt;

/*
	Simple vector, only useful for trivial objects
*/

template< class type >
struct vector {
	vector() : mBuffer(NULL), mAlloc(0), mItems(0) { Resize( 4 ); }
	~vector() { free( mBuffer ); }

	void Clear() { mItems = ( 0 ); }
	u32 Count() const { return ( mItems ); }
	void EnsureCapacity( u32 capacity ) { if ( capacity >= mAlloc ) Resize( capacity ); }
	vector &Push( const type &item ) { EnsureCapacity( mItems + 1 ); mBuffer[ mItems++ ] = ( item ); return ( *this ); }

	void Resize( u32 newsize ) {
		mAlloc = ( newsize << 1 );
		mBuffer = (type *)realloc( mBuffer, mAlloc * sizeof( type ) );
	}

	template< class Compare >
	void Sort( Compare comp ) {
		type *lower = ( mBuffer ), *upper = ( lower + mItems );
		for ( type *i = lower + 1; i < upper; ++i ) {
			type insert = ( *i ), *push = ( i - 1 );
	
			while ( push >= lower && comp( insert, push[0] ) ) {
				push[1] = ( push[0] );
				--push;
			}

			push[1] = ( insert );
		}
	}

	type &operator[] ( u32 index ) { return ( mBuffer[ index ] ); }

protected:
	type *mBuffer;
	u32 mAlloc, mItems;
};


/*
	Simple textfile writer
*/

struct textfile {
	textfile( const char *dir, const char *basename, const char *ext ) {
		_mkdir( dir );
		mFile = fopen( fmt( "%s\\%s.%s", dir, basename, ext ), "w+" );
	}

	~textfile() { if ( mFile ) fclose( mFile ); }
	textfile &operator<< ( const char *fragment ) { fputs( fragment, mFile ); return ( *this ); }
	textfile &operator<< ( u32 num ) { fprintf( mFile, "%u", num ); return ( *this ); }

protected:
	FILE *mFile;
};



/*
	Compares two objects which implement a getname() method
*/

template< class type >
struct namecompare {
	bool operator()( const type &a, const type &b ) const { 
		return ( _stricmp( a.getname(), b.getname() ) < 0 ); 
	}
};


/*
	Represents a single "export" and provides various ways of formatting it's name

	warning C4237: 'export' keyword is not yet supported, but reserved for future use
*/

struct export1 {
	export1( const char *name, u32 ordinal ) : mName(name), mOrdinal(ordinal) { mIsMangled = strchr( mName, '@' ) != NULL; }

	const char *getname() const { return ( mName ); }
	bool getismangled() const { return ( mIsMangled ); }

	// GetProcAddress( export )
	const char *togetprocaddress() { 
		if ( *mName )
			return fmt( "\"%s\"", mName );
		else
			return fmt( "(LPCSTR )%u", mOrdinal );
	}

	// .def file entry
	const char *toexport() { 
		if ( mIsMangled )
			return fmt( "%s=?decorated%u@@YGXXZ @%u", mName, mOrdinal, mOrdinal );
		else if ( *mName )
			return fmt( "%s=_%s @%u", mName, clean(mName), mOrdinal );
		else
			return fmt( "ordinal%u @%u NONAME", mOrdinal, mOrdinal );
	}
	
	// cpp function name
	const char *torawfunction() { 
		if ( *mName )
			return fmt( "_%s", clean(mName) );
		else
			return fmt( "ordinal%u", mOrdinal );
	}

	// dummy function name which jumps to cpp function if name is mangled
	const char *toproxyfunction() { 
		return fmt( "decorated%u", mOrdinal );
	}
protected:
	const char *clean( const char *mName ) {
		char *buf = fmt.getbuffer(), *out = buf;
		while ( *mName ) {
			char c = *mName++;
			if ( c == '?' || c == '@' || c == '$' )
				c = '_';
			*out++ = c;
		}
		*out = NULL;
		return ( buf );
	}

	const char *mName;
	u32 mOrdinal;
	bool mIsMangled;
};

/*
	A forwarded export
*/

struct forward {
	forward( const char *name, const char *forward, u32 ordinal ) : mName(name), mForwardName(forward), mOrdinal(ordinal) {}
	const char *getname() const { return ( mForwardName ); }
	const char *tolinker() { 
		return fmt( "%s=%s,@%u", mName, mForwardName, mOrdinal );
	}
	const char *toproxyfunction() { 
		return fmt( "%s", mName );
	}
protected:
	const char *mName, *mForwardName;
	u32 mOrdinal;
};



/*
	PE file processor
*/

struct pefile {
	pefile() : mBase(NULL) { }
	~pefile() { delete[] mBase; }

	void enumexports( vector<export1> &exportlist, vector<forward> &forwardlist ) {
		IMAGE_DATA_DIRECTORY *exportdir = &mNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
		IMAGE_EXPORT_DIRECTORY *exports = getptrfromrva<IMAGE_EXPORT_DIRECTORY>( exportdir->VirtualAddress );
		
		u32 *nametab = getptrfromrva<u32>( exports->AddressOfNames );
		u32 *functab = getptrfromrva<u32>( exports->AddressOfFunctions );
		u16 *ordtab = getptrfromrva<u16>( exports->AddressOfNameOrdinals );

		exportlist.Clear();
		forwardlist.Clear();
		
		for ( u32 i = 0; i < exports->NumberOfFunctions; i++ ) {
			// is this ordinal exported?
			if ( !functab[i] )
				continue;

			// see if the ordinal is named
			const char *name = "";
			for ( u32 idx = 0; idx < exports->NumberOfNames; idx++ ) {
				if ( ordtab[idx] == i ) {
					name = getptrfromrva<char>( nametab[idx] );
					break;
				}
			}

			// is it a foward?
			if ( functab[i] >= exportdir->VirtualAddress && functab[i] <= ( exportdir->VirtualAddress + exportdir->Size ) )
				forwardlist.Push( forward( name, getptrfromrva<char>( functab[i] ), exports->Base + i ) );
			else
				exportlist.Push( export1( name, exports->Base + i ) );
		}

		exportlist.Sort( namecompare<export1>() );
		forwardlist.Sort( namecompare<forward>() );
	}

	void grok( const char *filename ) {
		FILE *f = fopen( filename, "rb" );
		if (!f)
			throw "Unable to open";
		fseek( f, 0, SEEK_END );
		long size = ftell( f );
		fseek( f, 0, SEEK_SET );
		delete[] mBase;
		mSize = (size_t)size;
		mBase = new unsigned char[ mSize ];
		fread( mBase, mSize, 1, f );
		fclose( f );

		mNTHeader = (PIMAGE_NT_HEADERS)( mBase + ((IMAGE_DOS_HEADER *)mBase)->e_lfanew );
	}

protected:
	PIMAGE_SECTION_HEADER getsectionfromrva( u32 rva ) {
		PIMAGE_SECTION_HEADER section = ( IMAGE_FIRST_SECTION(mNTHeader) );

		for ( u16 i = 0; i < mNTHeader->FileHeader.NumberOfSections; i++, section++ ) {
			if ( ( rva >= section->VirtualAddress ) && ( rva < ( section->VirtualAddress + section->SizeOfRawData ) ) )
				return ( section );
		}

		throw "Invalid RVA";
	}

	template< class type >
	type *getptrfromrva( u32 rva ) {
		PIMAGE_SECTION_HEADER section = getsectionfromrva( rva );
		size_t offset = section->PointerToRawData + ( rva - section->VirtualAddress );
		if ( offset > mSize )
			throw "Valid RVA points outside of file";

		return (type *)( mBase + offset );
	}

protected:
	unsigned char *mBase;
	size_t mSize;
	PIMAGE_NT_HEADERS mNTHeader;
};


/*
	Idiotic GUID
*/

struct guid {
	guid() {
		static char *hex = "0123456789ABCDEF";
		srand( rand() * GetTickCount() );
		for ( u32 i = 1; i < 37; i++ )
			mGUID[i] = hex[rand()&0xf];
		mGUID[0] = '{';
		mGUID[9] = '-';
		mGUID[14] = '-';
		mGUID[19] = '-';
		mGUID[24] = '-';
		mGUID[37] = '}';
		mGUID[38] = '\x0';
	}
	const char *tostr() const { return ( mGUID ); }
protected:
	char mGUID[39];
};



/*
	Creates a project from a list of exports
*/

struct project {
	project( const char *basename, const char *convention, vector<export1> &exports, vector<forward> &forwards ) 
		: mBasename(basename), mConvention(convention), mExports(exports), mForwards(forwards) {}

	void create() {
		create_def();
		create_vcproj2003();
		create_sln2003();
		create_vcproj2005();
		create_sln2005();
		create_cpp();
		create_h();

		// old .suo files can make visual studio crash
		_unlink( fmt( "%s\\%s-2003.suo", mBasename, mBasename ) );
		_unlink( fmt( "%s\\%s-2005.suo", mBasename, mBasename ) );
	}
	
protected:
	void create_def() {
		textfile def( mBasename, mBasename, "def" );
		def << "EXPORTS\n";
		for ( u32 i = 0; i < mExports.Count(); i++ )
			def << mExports[i].toexport() << "\n";
	}

	void create_vcproj2003() {
		textfile vcproj( mBasename, fmt( "%s-2003", mBasename ), "vcproj" );

		vcproj <<	"<?xml version=\"1.0\" encoding=\"Windows-1252\"?>\n"
					"<VisualStudioProject\n"
					"	ProjectType=\"Visual C++\" Version=\"7.10\" Name=\"" << mBasename << "\" ProjectGUID=\"" << mVcprojId.tostr() << "\" Keyword=\"Win32Proj\">\n"
					"	<Platforms><Platform Name=\"Win32\"/></Platforms>\n"
					"	<Configurations>\n"
					"		<Configuration Name=\"Debug|Win32\" OutputDirectory=\"Debug\" IntermediateDirectory=\"Debug\" ConfigurationType=\"2\" CharacterSet=\"2\">\n"
					"			<Tool Name=\"VCCLCompilerTool\" Optimization=\"0\" PreprocessorDefinitions=\"WIN32;_DEBUG;_CONSOLE\" MinimalRebuild=\"TRUE\" BasicRuntimeChecks=\"3\" RuntimeLibrary=\"1\" UsePrecompiledHeader=\"0\" WarningLevel=\"3\" Detect64BitPortabilityProblems=\"FALSE\" DebugInformationFormat=\"4\"/>\n"
					"			<Tool Name=\"VCLinkerTool\" OutputFile=\"$(OutDir)/" << mBasename << ".dll\" LinkIncremental=\"2\" GenerateDebugInformation=\"TRUE\" ProgramDatabaseFile=\"$(OutDir)/" << mBasename << ".pdb\" SubSystem=\"1\" TargetMachine=\"1\" AdditionalOptions=\"/DEF:&quot;" << mBasename << ".def&quot;\" />\n"
					"		</Configuration>\n"
					"		<Configuration Name=\"Release|Win32\" OutputDirectory=\"Release\" IntermediateDirectory=\"Release\" ConfigurationType=\"2\" CharacterSet=\"2\">\n"
					"			<Tool Name=\"VCCLCompilerTool\" GlobalOptimizations=\"TRUE\" EnableIntrinsicFunctions=\"TRUE\" FavorSizeOrSpeed=\"1\" OmitFramePointers=\"TRUE\" OptimizeForProcessor=\"3\" PreprocessorDefinitions=\"WIN32;NDEBUG;_WINDOWS;_USRDLL;DLL_EXPORTS\" RuntimeLibrary=\"0\" BufferSecurityCheck=\"FALSE\" UsePrecompiledHeader=\"0\" WarningLevel=\"3\" Detect64BitPortabilityProblems=\"TRUE\" DebugInformationFormat=\"3\"/>\n"
					"			<Tool Name=\"VCLinkerTool\" OutputFile=\"$(OutDir)/" << mBasename << ".dll\" LinkIncremental=\"1\" GenerateDebugInformation=\"TRUE\" SubSystem=\"2\" OptimizeReferences=\"2\" EnableCOMDATFolding=\"2\" ImportLibrary=\"$(OutDir)/" << mBasename << ".lib\" TargetMachine=\"1\" AdditionalOptions=\"/DEF:&quot;" << mBasename << ".def&quot;\" />\n"
					"		</Configuration>\n"
					"	</Configurations>\n"
					"	<References></References>\n"
					"	<Files>\n"
					"		<Filter Name=\"Source Files\" Filter=\"cpp;c;cxx;def;odl;idl;hpj;bat;asm;asmx\" UniqueIdentifier=\"{4FC737F1-C7A5-4376-A066-2A32D752A2FF}\">\n"
					"			<File RelativePath=\".\\" << mBasename << ".cpp\"></File>\n"
					"		</Filter>\n"
					"		<Filter Name=\"Header Files\" Filter=\"h;hpp;hxx;hm;inl;inc;xsd\" UniqueIdentifier=\"{93995380-89BD-4b04-88EB-625FBE52EBFB}\">\n"
					"			<File RelativePath=\".\\" << mBasename << ".h\"></File>\n"
					"		</Filter>\n"
					"	</Files>\n"
					"	<Globals></Globals>\n"
					"</VisualStudioProject>\n";
	}

	void create_vcproj2005() {
		textfile vcproj( mBasename, fmt( "%s-2005", mBasename ), "vcproj" );

		vcproj <<	"<?xml version=\"1.0\" encoding=\"Windows-1252\"?>\n"
					"<VisualStudioProject \n"
					"	ProjectType=\"Visual C++\" Version=\"8.00\" Name=\"" << mBasename << "\" ProjectGUID=\"{" << mVcprojId.tostr() << "}\" RootNamespace=\"" << mBasename << "\" Keyword=\"Win32Proj\">\n"
					"	<Platforms><Platform Name=\"Win32\" /></Platforms>\n"
					"	<ToolFiles></ToolFiles>\n"
					"	<Configurations>\n"
					"		<Configuration Name=\"Debug|Win32\" OutputDirectory=\"$(SolutionDir)$(ConfigurationName)\" IntermediateDirectory=\"$(ConfigurationName)\" ConfigurationType=\"2\" CharacterSet=\"2\">\n"
					"			<Tool Name=\"VCCLCompilerTool\" Optimization=\"0\" PreprocessorDefinitions=\"WIN32;_DEBUG;_CONSOLE\" MinimalRebuild=\"true\" BasicRuntimeChecks=\"3\" RuntimeLibrary=\"1\" UsePrecompiledHeader=\"0\" WarningLevel=\"3\" Detect64BitPortabilityProblems=\"true\" DebugInformationFormat=\"4\" />\n"
					"			<Tool Name=\"VCLinkerTool\" LinkIncremental=\"2\" GenerateDebugInformation=\"true\" SubSystem=\"1\" TargetMachine=\"1\" AdditionalOptions=\"/DEF:&quot;" << mBasename << ".def&quot;\" />\n"
					"		</Configuration>\n"
					"		<Configuration Name=\"Release|Win32\" OutputDirectory=\"$(SolutionDir)$(ConfigurationName)\" IntermediateDirectory=\"$(ConfigurationName)\" ConfigurationType=\"2\" CharacterSet=\"2\" WholeProgramOptimization=\"1\">\n"
					"			<Tool Name=\"VCCLCompilerTool\" PreprocessorDefinitions=\"WIN32;NDEBUG;_CONSOLE\" RuntimeLibrary=\"0\" UsePrecompiledHeader=\"0\" WarningLevel=\"3\" Detect64BitPortabilityProblems=\"true\" DebugInformationFormat=\"3\" />\n"
					"			<Tool Name=\"VCLinkerTool\" LinkIncremental=\"1\" GenerateDebugInformation=\"true\" SubSystem=\"1\" OptimizeReferences=\"2\" EnableCOMDATFolding=\"2\" TargetMachine=\"1\" AdditionalOptions=\"/DEF:&quot;" << mBasename << ".def&quot;\" />\n"
					"		</Configuration>\n"
					"	</Configurations>\n"
					"	<References></References>\n"
					"	<Files>\n"
					"		<Filter Name=\"Source Files\" Filter=\"cpp;c;cc;cxx;def;odl;idl;hpj;bat;asm;asmx\" UniqueIdentifier=\"{4FC737F1-C7A5-4376-A066-2A32D752A2FF}\">\n"
					"			<File RelativePath=\".\\" << mBasename << ".cpp\"></File>\n"
					"		</Filter>\n"
					"		<Filter Name=\"Header Files\" Filter=\"h;hpp;hxx;hm;inl;inc;xsd\" UniqueIdentifier=\"{93995380-89BD-4b04-88EB-625FBE52EBFB}\">\n"
					"			<File RelativePath=\".\\" << mBasename << ".h\"></File>\n"
					"		</Filter>\n"
					"	</Files>\n"
					"	<Globals></Globals>\n"
					"</VisualStudioProject>\n";
	}

	void create_sln2003() {
		textfile sln( mBasename, fmt( "%s-2003", mBasename ), "sln" );
		
		sln <<	"Microsoft Visual Studio Solution File, Format Version 8.00\n"
				"Project(\"{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}\") = \"" << mBasename << "\", \"" << mBasename << "-2003.vcproj\", \"" << mVcprojId.tostr() << "\"\n"
				"	ProjectSection(ProjectDependencies) = postProject\n"
				"	EndProjectSection\n"
				"EndProject\n"
				"Global\n"
				"	GlobalSection(SolutionConfiguration) = preSolution\n"
				"		Debug = Debug\n"
				"		Release = Release\n"
				"	EndGlobalSection\n"
				"	GlobalSection(ProjectDependencies) = postSolution\n"
				"	EndGlobalSection\n"
				"	GlobalSection(ProjectConfiguration) = postSolution\n"
				"		" << mVcprojId.tostr() << ".Debug.ActiveCfg = Debug|Win32\n"
				"		" << mVcprojId.tostr() << ".Debug.Build.0 = Debug|Win32\n"
				"		" << mVcprojId.tostr() << ".Release.ActiveCfg = Release|Win32\n"
				"		" << mVcprojId.tostr() << ".Release.Build.0 = Release|Win32\n"
				"	EndGlobalSection\n"
				"	GlobalSection(ExtensibilityGlobals) = postSolution\n"
				"	EndGlobalSection\n"
				"	GlobalSection(ExtensibilityAddIns) = postSolution\n"
				"	EndGlobalSection\n"
				"EndGlobal\n";
	}

	void create_sln2005() {
		textfile sln( mBasename, fmt( "%s-2005", mBasename ), "sln" );
		
		sln <<	"Microsoft Visual Studio Solution File, Format Version 9.00\n"
				"# Visual Studio 2005\n"
				"Project(\"{8BC9CEB8-8B4A-11D0-8D11-00A0C91BC942}\") = \"" << mBasename << "\", \"" << mBasename << "-2005.vcproj\", \"" << mVcprojId.tostr() << "\"\n"
				"EndProject\n"
				"Global\n"
				"	GlobalSection(SolutionConfigurationPlatforms) = preSolution\n"
				"		Debug|Win32 = Debug|Win32\n"
				"		Release|Win32 = Release|Win32\n"
				"	EndGlobalSection\n"
				"	GlobalSection(ProjectConfigurationPlatforms) = postSolution\n"
				"		" << mVcprojId.tostr() << ".Debug|Win32.ActiveCfg = Debug|Win32\n"
				"		" << mVcprojId.tostr() << ".Debug|Win32.Build.0 = Debug|Win32\n"
				"		" << mVcprojId.tostr() << ".Release|Win32.ActiveCfg = Release|Win32\n"
				"		" << mVcprojId.tostr() << ".Release|Win32.Build.0 = Release|Win32\n"
				"	EndGlobalSection\n"
				"	GlobalSection(SolutionProperties) = preSolution\n"
				"		HideSolutionNode = FALSE\n"
				"	EndGlobalSection\n"
				"EndGlobal\n";
	}

	void create_cpp() {
		textfile cpp( mBasename, mBasename, "cpp" );
		cpp <<	"#define _CRT_SECURE_NO_WARNINGS\n\n"
				"#include <windows.h>\n"
				"#include <stdio.h>\n"
				"#include \"" << mBasename << ".h\"\n\n";

		for ( u32 i = 0; i < mForwards.Count(); i++ )
			cpp << "#pragma comment(linker, \"/export:" << mForwards[i].tolinker() << "\")\n";

		cpp <<	"\nHINSTANCE mHinst, mHinstDLL;\n"
				"FARPROC mProcs[" << mExports.Count() << "];\n\n";

		cpp << "LPCSTR mImportNames[] = {\n	";
		for ( u32 i = 0, perline = 1; i < mExports.Count(); i++, perline++ ) {
			cpp << mExports[i].togetprocaddress() << ", ";
			if ( perline % 4 == 0 && ( perline != mExports.Count() ) )
				cpp << "\n	";
		}
		cpp << "\n};\n\n";

		cpp <<	"BOOL WINAPI DllMain( HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved ) {\n"
				"	mHinst = hinstDLL;\n"
				"	if ( fdwReason == DLL_PROCESS_ATTACH ) {\n"
				"		char sysdir[255], path[255];\n"
				"		GetSystemDirectory( sysdir, 254 );\n"
				"		sprintf( path, \"%s\\\\" << mBasename << ".dll\", sysdir );\n"
				"		mHinstDLL = LoadLibrary( path );\n"
				"		if ( !mHinstDLL )\n"
				"			return ( FALSE );\n\n"
				"		for ( int i = 0; i < " << mExports.Count() << "; i++ )\n"
				"			mProcs[ i ] = GetProcAddress( mHinstDLL, mImportNames[ i ] );\n"
				"	} else if ( fdwReason == DLL_PROCESS_DETACH ) {\n"
				"		FreeLibrary( mHinstDLL );\n"
				"	}\n"
				"	return ( TRUE );\n"
				"}\n\n";
		
		for ( u32 i = 0; i < mExports.Count(); i++ ) {
			#if defined(UNMANGLE)
				char *unmangled = fmt.getbuffer();
				UnDecorateSymbolName( mExports[i].getname(), unmangled, fmt.getbuffersize(), UNDNAME_COMPLETE );
				cpp <<	"// " << unmangled << "\n";
			#endif

			cpp <<	"int " << mConvention << " " << mExports[i].torawfunction() << "() {\n"
					"	return call" << mExports[i].torawfunction() << "();\n"
					"}\n\n";
		}

		// mangled placeholders
		for ( u32 i = 0; i < mExports.Count(); i++ ) {
			if ( !mExports[i].getismangled() )
				continue;

			cpp << "naked void " << mConvention << " " << mExports[i].toproxyfunction() << "() { __asm { jmp " << mExports[i].torawfunction() << " } }\n";
		}
	}

	void create_h() {
		textfile h( mBasename, mBasename, "h" );
		h	<< "#ifndef __" << mBasename << "_h__\n"
			<< "#define __" << mBasename << "_h__\n\n";

		h	<< "	#define naked __declspec(naked)\n"
			<< "	#define inline __forceinline\n\n\n"
			<< "	extern FARPROC mProcs[];\n";

		for ( u32 i = 0; i < mExports.Count(); i++ )
			h << "	inline naked int call" << mExports[i].torawfunction() << "() { __asm { jmp dword ptr [ mProcs + " << i << " * 4 ] } }\n";

		h << "\n#endif // __" << mBasename << "_h__\n";
	}

	const char *mBasename, *mConvention;
	vector<export1> &mExports;
	vector<forward> &mForwards;
	guid mVcprojId;
};


char *getbasename( const char *name, char *basename ) {
	char *start = ( basename );
	while ( *name && *name != '.' )
		*basename++ = *name++;
	*basename = '\x0';
	return ( start );
}

int main( int argc, const char *argv[] ) {
	const char *file = ( argc > 1 ) ? argv[1] : "dll.dll";
	const char *convention = ( argc > 2 ) ? argv[2] : "__stdcall";

	pefile pe;
	vector<export1> exports;
	vector<forward> forwards;
	
	try {
		pe.grok( file );
		pe.enumexports( exports, forwards );
	} catch (const char *reason) {
		printf( "%s: %s\n", file, reason );
		return ( -1 );
	}

	char basename[512];
	project( getbasename( file, basename ), convention, exports, forwards ).create();
	return ( 0 );
}