#ifndef SRC_CSR_H
#define SRC_CSR_H


#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#include <node.h>


class CSR : public node::ObjectWrap {
 public:
  static void Initialize(v8::Handle<v8::Object> target);

 private:
  CSR();
  ~CSR();

  static v8::Handle<v8::Value> New(const v8::Arguments& args);
  static v8::Handle<v8::Value> GetSubject(const v8::Arguments& args);
  X509_REQ *xr;
};

#endif
