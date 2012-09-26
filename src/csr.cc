#include <node.h>
#include <node_buffer.h>

#include "csr.h"

using namespace v8;


// Copied from node.js src/node_crypto.cc
// Takes a string or buffer and loads it into a BIO.
// Caller responsible for BIO_free-ing the returned object.
static BIO *LoadBIO (Handle<Value> v) {
  BIO *bio = BIO_new(BIO_s_mem());
  if (!bio) return NULL;

  HandleScope scope;

  int r = -1;

  if (v->IsString()) {
    String::Utf8Value s(v);
    r = BIO_write(bio, *s, s.length());
  } else if (node::Buffer::HasInstance(v)) {
    Local<Object> buffer_obj = v->ToObject();
    char *buffer_data = node::Buffer::Data(buffer_obj);
    size_t buffer_length = node::Buffer::Length(buffer_obj);
    r = BIO_write(bio, buffer_data, buffer_length);
  }

  if (r <= 0) {
    BIO_free(bio);
    return NULL;
  }

  return bio;
}



CSR::CSR() {};
CSR::~CSR() {
  X509_REQ_free(this->xr);
};

void CSR::Initialize(Handle<Object> target) {
  Local<FunctionTemplate> t = FunctionTemplate::New(New);
  t->InstanceTemplate()->SetInternalFieldCount(1);
  t->SetClassName(String::NewSymbol("CSR"));

  NODE_SET_PROTOTYPE_METHOD(t, "_getSubject", GetSubject);

  target->Set(String::NewSymbol("CSR"), t->GetFunction());
}

Handle<Value> CSR::New(const Arguments& args) {
  HandleScope scope;

  if (args.Length() != 1) {
    return ThrowException(Exception::TypeError(String::New("Bad parameter")));
  }

  BIO *bio = LoadBIO(args[0]);
  if (!bio) {
    return ThrowException(Exception::TypeError(String::New("Invalid parameter")));
  }

  CSR *obj = new CSR();

  obj->xr = PEM_read_bio_X509_REQ(bio, NULL, NULL, NULL);
  if (!obj->xr) {
    BIO_free(bio);
    return ThrowException(Exception::TypeError(String::New("Invalid parameter")));
  }

  BIO_free(bio);


  obj->Wrap(args.This());

  return args.This();
}


static const int X509_NAME_FLAGS = ASN1_STRFLGS_ESC_CTRL
                                 | ASN1_STRFLGS_ESC_MSB
                                 | XN_FLAG_SEP_MULTILINE
                                 | XN_FLAG_FN_SN
                                 ;

Handle<Value> CSR::GetSubject(const Arguments& args) {
  HandleScope scope;

  CSR *csr = ObjectWrap::Unwrap<CSR>(args.This());
  Local<String> str;


  X509_NAME *subject = subject = X509_REQ_get_subject_name(csr->xr);

  BIO *bio = BIO_new(BIO_s_mem());
  BUF_MEM *mem;
  if (X509_NAME_print_ex(bio, subject, 0, X509_NAME_FLAGS) > 0) {
    BIO_get_mem_ptr(bio, &mem);
    str = String::New(mem->data, mem->length);
  }
  (void) BIO_reset(bio);


  return scope.Close(str);
}
