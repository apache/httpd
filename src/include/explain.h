#ifndef EXPLAIN
#define DEF_Explain
#define Explain0(f)
#define Explain1(f,a1)
#define Explain2(f,a1,a2)
#define Explain3(f,a1,a2,a3)
#define Explain4(f,a1,a2,a3,a4)
#define Explain5(f,a1,a2,a3,a4,a5)
#define Explain6(f,a1,a2,a3,a4,a5,a6)
#else
#define DEF_Explain	static const char *__ExplainFile=__FILE__;
void _Explain(const char *szFile,int nLine,const char *szFmt,...);
#define Explain0(f)	_Explain(__ExplainFile,__LINE__,f)
#define Explain1(f,a1)	_Explain(__ExplainFile,__LINE__,f,a1)
#define Explain2(f,a1,a2)	_Explain(__ExplainFile,__LINE__,f,a1,a2)
#define Explain3(f,a1,a2,a3)	_Explain(__ExplainFile,__LINE__,f,a1,a2,a3)
#define Explain4(f,a1,a2,a3,a4)	_Explain(__ExplainFile,__LINE__,f,a1,a2,a3,a4)
#define Explain5(f,a1,a2,a3,a4,a5)	\
			_Explain(__ExplainFile,__LINE__,f,a1,a2,a3,a4,a5)
#define Explain6(f,a1,a2,a3,a4,a5,a6)	\
			_Explain(__ExplainFile,__LINE__,f,a1,a2,a3,a4,a5,a6)

#endif
