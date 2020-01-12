#ifndef HCL_CORE_LIBRARY_H
#define HCL_CORE_LIBRARY_H

extern "C" char *GetBasicAuth(const char *raw_email, const char *raw_password);
extern "C" void ReleaseAllocatedMemory(void *pointer);

#endif //HCL_CORE_LIBRARY_H
