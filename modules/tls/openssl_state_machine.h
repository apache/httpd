typedef struct SSLStateMachine SSLStateMachine;

void SSLStateMachine_init(void);
SSLStateMachine *SSLStateMachine_new(const char *szCertificateFile,
				     const char *szKeyFile);
void SSLStateMachine_destroy(SSLStateMachine *pMachine);
void SSLStateMachine_read_inject(SSLStateMachine *pMachine,
				 const unsigned char *aucBuf,int nBuf);
int SSLStateMachine_read_extract(SSLStateMachine *pMachine,
				 unsigned char *aucBuf,int nBuf);
int SSLStateMachine_write_can_extract(SSLStateMachine *pMachine);
int SSLStateMachine_write_extract(SSLStateMachine *pMachine,
				  unsigned char *aucBuf,int nBuf);
void SSLStateMachine_write_inject(SSLStateMachine *pMachine,
				  const unsigned char *aucBuf,int nBuf);
void SSLStateMachine_write_close(SSLStateMachine *pMachine);
