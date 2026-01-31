#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#ifdef __EMSCRIPTEN__
#include <emscripten/emscripten.h>
#define DONUT_WASM_EXPORT EMSCRIPTEN_KEEPALIVE
#else
#define DONUT_WASM_EXPORT
#endif

#include "../donut.c"

typedef struct donut_wasm_result {
    uint32_t ptr;
    uint32_t len;
    int32_t err;
} donut_wasm_result;

static int read_file_info_mem(PDONUT_CONFIG c, const uint8_t *data, uint32_t len, const char *ext) {
    PIMAGE_NT_HEADERS   nt;
    PIMAGE_DATA_DIRECTORY dir;
    PMDSTORAGESIGNATURE pss;
    PIMAGE_COR20_HEADER cor;
    DWORD               dll, rva, cpu;
    ULONG64             ofs;
    const char          *extp;
    int                 err = DONUT_ERROR_OK;

    if(c == NULL || data == NULL || len == 0) {
      return DONUT_ERROR_INVALID_PARAMETER;
    }
    if(ext == NULL || ext[0] == 0) {
      return DONUT_ERROR_FILE_INVALID;
    }

    memset(&fi, 0, sizeof(fi));
    fi.data = (uint8_t*)data;
    fi.len = len;

    extp = ext;

    if(extp[0] == '.') {
      extp++;
    }

    if(strcasecmp(extp, "vbs") == 0) {
      fi.type = DONUT_MODULE_VBS;
      fi.arch = DONUT_ARCH_ANY;
    } else if(strcasecmp(extp, "js") == 0) {
      fi.type = DONUT_MODULE_JS;
      fi.arch = DONUT_ARCH_ANY;
    } else if(strcasecmp(extp, "exe") == 0) {
      fi.type = DONUT_MODULE_EXE;
    } else if(strcasecmp(extp, "dll") == 0) {
      fi.type = DONUT_MODULE_DLL;
    } else {
      return DONUT_ERROR_FILE_INVALID;
    }

    if(fi.type == DONUT_MODULE_DLL || fi.type == DONUT_MODULE_EXE) {
      if(!valid_dos_hdr(fi.data)) {
        err = DONUT_ERROR_FILE_INVALID;
        goto cleanup;
      }
      if(!valid_nt_hdr(fi.data)) {
        err = DONUT_ERROR_FILE_INVALID;
        goto cleanup;
      }

      dir = Dirs(fi.data);
      if(dir == NULL) {
        err = DONUT_ERROR_FILE_INVALID;
        goto cleanup;
      }

      nt  = NtHdr(fi.data);
      dll = nt->FileHeader.Characteristics & IMAGE_FILE_DLL;
      cpu = is32(fi.data);
      rva = dir[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;

      fi.arch = cpu ? DONUT_ARCH_X86 : DONUT_ARCH_X64;

      if(rva != 0) {
        if(dir[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress != 0) {
          err = DONUT_ERROR_MIXED_ASSEMBLY;
          goto cleanup;
        } else {
          fi.type = (dll) ? DONUT_MODULE_NET_DLL : DONUT_MODULE_NET_EXE;
          strncpy(fi.ver, "v4.0.30319", DONUT_VER_LEN - 1);
          ofs = rva2ofs(fi.data, rva);
          if(ofs != (ULONG64)-1) {
            cor = (PIMAGE_COR20_HEADER)(ofs + fi.data);
            rva = cor->MetaData.VirtualAddress;
            if(rva != 0) {
              ofs = rva2ofs(fi.data, rva);
              if(ofs != (ULONG64)-1) {
                pss = (PMDSTORAGESIGNATURE)(ofs + fi.data);
                strncpy(fi.ver, (char*)pss->pVersion, DONUT_VER_LEN - 1);
              }
            }
          }
        }
      }
    }

    c->len = fi.len;
    c->mod_type = fi.type;

cleanup:
    if(err != DONUT_ERROR_OK) {
      fi.data = NULL;
      fi.len = 0;
    }
    return err;
}

DONUT_WASM_EXPORT int donut_generate(const uint8_t *input,
                                     uint32_t input_len,
                                     const char *ext,
                                     const char *args,
                                     const char *cls,
                                     const char *method,
                                     uint32_t arch,
                                     uint32_t entropy,
                                     uint32_t compress,
                                     uint32_t exit_opt,
                                     donut_wasm_result *out) {
    DONUT_CONFIG c;
    int err = DONUT_ERROR_OK;
    uint8_t *out_buf = NULL;

    if(out == NULL) {
      return DONUT_ERROR_INVALID_PARAMETER;
    }

    out->ptr = 0;
    out->len = 0;
    out->err = DONUT_ERROR_INVALID_PARAMETER;

    if(input == NULL || input_len == 0 || ext == NULL || ext[0] == 0) {
      return DONUT_ERROR_INVALID_PARAMETER;
    }

    memset(&c, 0, sizeof(c));

    c.inst_type = DONUT_INSTANCE_EMBED;
    c.arch = (arch == 0) ? DONUT_ARCH_X84 : (int)arch;
    c.bypass = DONUT_BYPASS_CONTINUE;
    c.headers = DONUT_HEADERS_OVERWRITE;
    c.format = DONUT_FORMAT_BINARY;
    c.compress = (compress == 0) ? DONUT_COMPRESS_NONE : (int)compress;
    c.entropy = (entropy == 0) ? DONUT_ENTROPY_NONE : (int)entropy;
    c.exit_opt = (exit_opt == 0) ? DONUT_OPT_EXIT_THREAD : (int)exit_opt;
    c.unicode = 0;

    strncpy(c.input, "memory", DONUT_MAX_NAME - 1);

    if(args != NULL && args[0] != 0) {
      strncpy(c.args, args, DONUT_MAX_NAME - 1);
    }
    if(cls != NULL && cls[0] != 0) {
      strncpy(c.cls, cls, DONUT_MAX_NAME - 1);
    }
    if(method != NULL && method[0] != 0) {
      strncpy(c.method, method, DONUT_MAX_NAME - 1);
    }

    c.mod = c.pic = c.inst = NULL;
    c.mod_len = c.pic_len = c.inst_len = 0;

    err = validate_loader_cfg(&c);
    if(err == DONUT_ERROR_OK) {
      err = read_file_info_mem(&c, input, input_len, ext);
      if(err == DONUT_ERROR_OK) {
        err = validate_file_cfg(&c);
        if(err == DONUT_ERROR_OK) {
          err = build_module(&c);
          if(err == DONUT_ERROR_OK) {
            err = build_instance(&c);
            if(err == DONUT_ERROR_OK) {
              err = build_loader(&c);
            }
          }
        }
      }
    }

    if(err == DONUT_ERROR_OK) {
      out_buf = (uint8_t*)malloc(c.pic_len);
      if(out_buf == NULL) {
        err = DONUT_ERROR_NO_MEMORY;
      } else {
        memcpy(out_buf, c.pic, c.pic_len);
        out->ptr = (uint32_t)(uintptr_t)out_buf;
        out->len = c.pic_len;
        out->err = DONUT_ERROR_OK;
      }
    }

    if(err != DONUT_ERROR_OK) {
      out->err = err;
    }

    fi.data = NULL;
    fi.len = 0;
    fi.fd = 0;

    DonutDelete(&c);

    return err;
}
