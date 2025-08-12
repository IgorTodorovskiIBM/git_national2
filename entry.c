#define USE_THE_REPOSITORY_VARIABLE
#define _AE_BIMODAL 1

#include "git-compat-util.h"
#include "object-store-ll.h"
#include "dir.h"
#include "environment.h"
#include "gettext.h"
#include "hex.h"
#include "name-hash.h"
#include "sparse-index.h"
#include "streaming.h"
#include "submodule.h"
#include "symlinks.h"
#include "progress.h"
#include "fsmonitor.h"
#include "entry.h"
#include "parallel-checkout.h"

#ifdef __MVS__ 


#include "environment.h"   

#include <iconv.h>
#include <errno.h>
#include <_Nascii.h>

extern const char *get_worktree_filename_encoding(void);


// Helper function to perform the core iconv conversion.
// Returns a newly allocated string or NULL on error.
static char *do_iconv_convert(const char *input_str, const char *to_enc, const char *from_enc) {
    if (!input_str || !to_enc || !from_enc || strcmp(to_enc, from_enc) == 0) {
        // If no input, or encodings are the same, or no specific encoding,
        // just duplicate the string (or return NULL if that's preferred for "no conversion")
        // For filename paths, it's often better to xstrdup to maintain ownership consistency.
        return input_str ? xstrdup(input_str) : NULL;
    }

    iconv_t cd;
    char *original_input_ptr = (char *)input_str; // iconv() modifies inbuf
    size_t input_len = strlen(input_str);
    
    // Estimate output buffer size. For UTF-8 <-> EBCDIC (single byte focus),
    // output_len is often <= input_len * 2 (worst case for some chars to UTF-8 can be 3 bytes).
    // A safer bet for general conversion might be input_len * 4 for max UTF-8 expansion, plus null.
    // Let's start with a reasonable multiplier. Max USS path is 1023.
    size_t output_buffer_size = (input_len * 2) + 1; // Initial conservative estimate, +1 for null
    if (output_buffer_size < 128) output_buffer_size = 128; // Minimum buffer

    char *output_buffer = xmalloc(output_buffer_size);
    char *output_ptr = output_buffer;
    size_t output_len_avail = output_buffer_size - 1; // Reserve space for null terminator

    cd = iconv_open(to_enc, from_enc);
    if (cd == (iconv_t)-1) {
        //error("iconv_open from '%s' to '%s' failed: %s", from_enc, to_enc, strerror(errno));
        // Potentially check get_filename_conversion_error_policy() here if you want
        // different behavior than just erroring out (e.g., return original string).
        free(output_buffer);
        return NULL; // Or xstrdup(input_str) if policy is to bypass on error
    }

    size_t iconv_ret = iconv(cd, &original_input_ptr, &input_len, &output_ptr, &output_len_avail);

    if (iconv_ret == (size_t)-1) {
        error("iconv conversion from '%s' to '%s' for input '%.*s...' failed: %s (errno %d)",
              from_enc, to_enc, 20, input_str, strerror(errno), errno);
        // TODO: Implement error policy from get_filename_conversion_error_policy()
        // For EILSEQ/EINVAL: substitute, error, or return original?
        // For E2BIG: reallocate output_buffer and retry (more complex).
        // For now, fail by returning NULL.
        iconv_close(cd);
        free(output_buffer);
        return NULL; // Or xstrdup(input_str) if policy is to bypass
    }
    *output_ptr = '\0'; // Null-terminate the converted string

    if (iconv_close(cd) != 0) {
        warning("iconv_close after converting from '%s' to '%s' failed: %s",
                from_enc, to_enc, strerror(errno));
        // Conversion succeeded, so we can still use the result.
    }

    // It's possible the buffer was overallocated.
    // To save memory, you could realloc down to strlen(output_buffer) + 1,
    // or simply return a strdup of the buffer up to the actual length.
    // For simplicity now, we return the potentially larger buffer.
    // A strdup is safer:
    // char *final_result = xstrdup(output_buffer);
    // free(output_buffer);
    // return final_result;
    // However, xstrdup after filling is an extra copy.
    // For now, let's assume output_buffer is okay.
    // A better approach if reallocating is not done for E2BIG:
    // char *shrunk_buffer = xrealloc(output_buffer, (output_ptr - output_buffer) + 1);
    // return shrunk_buffer;
    // For simplicity, let's just return what we have.
    return output_buffer;
}

char *git_utf8_to_worktree_enc(const char *utf8_str) {
    const char *target_enc = get_worktree_filename_encoding(); // From config.c accessors
    if (!target_enc || strcmp(target_enc, "UTF-8") == 0) {
        // No conversion needed, or target is UTF-8
        return utf8_str ? xstrdup(utf8_str) : NULL;
    }
    return do_iconv_convert(utf8_str, target_enc, "UTF-8");
}

char *git_worktree_enc_to_utf8(const char *worktree_enc_str) {
    const char *source_enc = get_worktree_filename_encoding(); // From config.c accessors
    if (!source_enc || strcmp(source_enc, "UTF-8") == 0) {
        // No conversion needed, or source is already UTF-8 (should not happen if configured)
        return worktree_enc_str ? xstrdup(worktree_enc_str) : NULL;
    }
    return do_iconv_convert(worktree_enc_str, "UTF-8", source_enc);
}

int zos_access(const char *path, int mode) {
#ifdef __MVS__
    const char *target_encoding = get_worktree_filename_encoding();
    bool isConverted = false;
    char* converted_path = NULL;
    int ret = -1;
    int saved_errno_call = 0;

    if (target_encoding && strcmp(target_encoding, "UTF-8") != 0) {
        converted_path = git_utf8_to_worktree_enc(path);
        if (!converted_path) {
            if (errno == 0) errno = EILSEQ;
            return -1;
        }
        isConverted = true;
    }

    if (isConverted) {
        trace_printf("zos_access: EBCDIC path for '%s' (orig: '%s') with encoding '%s'\n", converted_path, path, target_encoding);
        int original_thread_mode = __ae_thread_swapmode(__AE_EBCDIC_MODE);
        ret = __access_e(converted_path, mode); // Assuming __access_e exists
        saved_errno_call = errno;
        __ae_thread_swapmode(original_thread_mode);
        errno = saved_errno_call;
        free(converted_path);
        return ret;
    } else {
        trace_printf("zos_access: ASCII path for '%s'\n", path);
        return __access_a(path, mode); // Using standard access
    }
#else // Not __MVS__
    return access(path, mode);
#endif
}

// This version modifies a static struct dirent to return UTF-8 d_name.
struct dirent *zos_readdir(DIR *dirp) {
#ifdef __MVS__
    static struct dirent static_de_buffer; // Static buffer for the returned dirent
    // Ensure d_name is large enough. POSIX NAME_MAX is usually 255.
    // If struct dirent has d_name as char d_name[], this static buffer approach is okay.
    // If d_name is char *d_name, this approach needs careful thought about memory management
    // for d_name itself if it's dynamically allocated. Standard readdir returns a pointer
    // to a static struct or one within the DIR structure.

    struct dirent *de_sys; // Pointer to dirent from system readdir

    // Assuming dirp was opened by zos_opendir, which would have handled
    // EBCDIC mode for the stream if __opendir_e was used.
    // If using standard readdir() and the stream is EBCDIC, d_name will be EBCDIC.
    // If a __readdir_e exists and should be used, wrap it with __ae_thread_swapmode.
    // For this example, let's assume standard readdir() is called on the (potentially EBCDIC) stream.
    
    int original_thread_mode = __ae_thread_swapmode(__AE_EBCDIC_MODE); // If calling __readdir_e
    de_sys = __readdir_e(dirp); // Or perhaps __readdir_e(dirp)
    __ae_thread_swapmode(original_thread_mode); // If calling __readdir_e
    
    if (!de_sys) {
        return NULL; // End of directory or error
    }

    // Copy essential members from system's dirent to our static buffer
    // The members available in struct dirent can vary.
    // d_ino is POSIX standard. d_type is a common BSD/Linux extension.
    static_de_buffer.d_ino = de_sys->d_ino;
    #if defined(HAVE_STRUCT_DIRENT_D_TYPE) || defined(_DIRENT_HAVE_D_TYPE) || defined(__USE_BSD) || defined(__DARWIN_UNIX03)
    static_de_buffer.d_type = de_sys->d_type;
    #else
    // If d_type is not available, you might need to stat the file to get its type,
    // or Git's calling code handles this. For now, set to unknown if not available.
    // static_de_buffer.d_type = DT_UNKNOWN; // DT_UNKNOWN is usually defined
    #endif
    // Other members like d_off, d_reclen are less commonly used directly by Git's core logic
    // for filename processing, but copy if necessary for your Git version/usage.

    const char *target_encoding = get_worktree_filename_encoding();
    if (target_encoding) { // && strcmp(target_encoding, "UTF-8") != 0) {
        // de_sys->d_name is EBCDIC, convert it to UTF-8
        char *utf8_name = git_worktree_enc_to_utf8(de_sys->d_name);
        if (!utf8_name) {
            if (errno == 0 && de_sys->d_name[0] != '\0') {
                 errno = EILSEQ;
            }
            warning_errno("zos_readdir: Failed to convert d_name (len %d, starts 0x%02X) from EBCDIC to UTF-8 for entry in dir opened via zos_opendir. Returning NULL for this entry.",
                          (int)strlen(de_sys->d_name), (unsigned char)de_sys->d_name[0]);
            return NULL; // Skip this entry by returning NULL
        }

        // Copy the converted UTF-8 name into our static buffer's d_name field.
        // Ensure null termination and protect against overflow.
        // sizeof(static_de_buffer.d_name) refers to the size of the array in struct dirent.
        strlcpy(static_de_buffer.d_name, utf8_name, sizeof(static_de_buffer.d_name) - 1);
        static_de_buffer.d_name[sizeof(static_de_buffer.d_name) - 1] = '\0';
        
        trace_printf("zos_readdir: converted EBCDIC d_name (orig starts 0x%02X) to UTF-8 d_name '%s'\n", 
            (unsigned char)de_sys->d_name[0], static_de_buffer.d_name);
        
        free(utf8_name); // We copied it, so free the allocated buffer
    } else {
        // No conversion needed, or worktree_enc is already UTF-8.
        // Copy original d_name (which should be UTF-8 compatible).
        strlcpy(static_de_buffer.d_name, de_sys->d_name, sizeof(static_de_buffer.d_name) - 1);
        static_de_buffer.d_name[sizeof(static_de_buffer.d_name) - 1] = '\0';
        trace_printf("zos_readdir: using ASCII/UTF-8 d_name '%s'\n", static_de_buffer.d_name);
    }
    
    return &static_de_buffer;

#else // Not __MVS__
    return readdir(dirp);
#endif
}

char *zos_realpath(const char *path, char *resolved_path) {
#ifdef __MVS__
    const char *target_encoding = get_worktree_filename_encoding();
    char *return_ptr = NULL;

    if (target_encoding && strcmp(target_encoding, "UTF-8") != 0) {
        char *converted_path = git_utf8_to_worktree_enc(path);
        if (!converted_path) {
            if (errno == 0) errno = EILSEQ;
            return NULL;
        }

        // Allocate a buffer for the EBCDIC resolved path from __realpath_e
        char *ebcdic_resolved_path = xmalloc(PATH_MAX + 1);

        trace_printf("zos_realpath: EBCDIC path for '%s' (orig: '%s') with encoding '%s'\n",
                     converted_path, path, target_encoding);
        
        int original_thread_mode = __ae_thread_swapmode(__AE_EBCDIC_MODE);
        // Call the EBCDIC-aware realpath variant
        char *e_res = __realpath_e(converted_path, ebcdic_resolved_path);
        int saved_errno_call = errno;
        __ae_thread_swapmode(original_thread_mode);
        errno = saved_errno_call;

        free(converted_path); // Free the converted input path

        if (e_res) { // __realpath_e succeeded
            // The content of ebcdic_resolved_path is EBCDIC. Convert it back to UTF-8.
            char *final_utf8_path = git_worktree_enc_to_utf8(ebcdic_resolved_path);
            if (!final_utf8_path) {
                trace_printf("zos_realpath: Failed to convert EBCDIC resolved path to UTF-8 for original path '%s'\n", path);
                if (errno == 0) errno = EILSEQ;
                return_ptr = NULL; // Indicate conversion error
            } else {
                if (resolved_path) {
                    // Caller provided a buffer, copy the UTF-8 result into it.
                    strlcpy(resolved_path, final_utf8_path, PATH_MAX); // Assuming caller's buffer is PATH_MAX
                    return_ptr = resolved_path;
                    free(final_utf8_path); // Free the temp UTF-8 buffer
                } else {
                    // Caller wants us to allocate the buffer. Return the one we made.
                    return_ptr = final_utf8_path;
                }
            }
        } else { // __realpath_e failed, errno is set
            return_ptr = NULL;
        }
        
        free(ebcdic_resolved_path); // Free the EBCDIC result buffer
        return return_ptr;

    } else { // Not converted (standard ASCII path)
        trace_printf("zos_realpath: ASCII path for '%s'\n", path);
        // Call the ASCII-aware realpath variant as requested
        return __realpath_a(path, resolved_path);
    }
#else // Not __MVS__
    return realpath(path, resolved_path);
#endif
}


// Your zos_open function
int zos_open(const char *path, int flags, ...) {
    va_list ap;
    va_start(ap, flags);
    // mode_t perms = va_arg(ap, mode_t); // Using mode_t is technically more correct
    int perms_int = 0; // Default if not O_CREAT
    if (flags & O_CREAT) {
        perms_int = va_arg(ap, int); // As per your original usage
    }
    mode_t perms = (mode_t)perms_int;
    va_end(ap);

#ifdef __MVS__
    const char *target_encoding = get_worktree_filename_encoding();
    bool isConverted = false;
    char* converted_path = NULL;
    int fd = -1;
    int saved_errno_call = 0;

    if (target_encoding && strcmp(target_encoding, "UTF-8") != 0) {
        converted_path = git_utf8_to_worktree_enc(path);
        if (!converted_path) {
            if (errno == 0) errno = EILSEQ;
            // git_utf8_to_worktree_enc should ideally call error_errno for detailed iconv errors
            return -1;
        }
        isConverted = true;
    }

    if (isConverted) {
        trace_printf("zos_open: EBCDIC path for '%s' (orig: '%s') with encoding '%s'\n", converted_path, path, target_encoding);
        int original_thread_mode = __ae_thread_swapmode(__AE_EBCDIC_MODE);
        if (flags & O_CREAT) {
             fd = __open_e(converted_path, flags, perms);
        } else {
             fd = __open_e(converted_path, flags);
        }
        saved_errno_call = errno;
        __ae_thread_swapmode(original_thread_mode);
        errno = saved_errno_call; // Restore errno from the actual syscall
        free(converted_path);
        return fd;
    } else {
        trace_printf("zos_open: ASCII path for '%s'\n", path);
        return __open_ascii(path, flags, perms); // Using standard open
    }
#else // Not __MVS__
    // Standard open for non-z/OS builds
   return __open_ascii(path, flags, perms); // Using standard open
#endif
}

char *__ptr32 *__ptr32 __uss_base_address(void) {
  static char *__ptr32 *__ptr32 res = 0;
  if (res == 0) {
    res = ((char *__ptr32 *__ptr32 *__ptr32 *__ptr32 *)0)[4][136][6];
  }
  return res;
}


// Wrapper for stat
int zos_stat(const char *path, struct stat *buf) {
#ifdef __MVS__
    const char *target_encoding = get_worktree_filename_encoding();
    bool isConverted = false;
    char* converted_path = NULL;
    int ret = -1;
    int saved_errno_call = 0;

    if (target_encoding && strcmp(target_encoding, "UTF-8") != 0) {
        converted_path = git_utf8_to_worktree_enc(path);
        if (!converted_path) {
            if (errno == 0) errno = EILSEQ;
            return -1;
        }
        isConverted = true;
    }

    if (isConverted) {
        trace_printf("zos_stat: EBCDIC path for '%s' (orig: '%s') with encoding '%s'\n", converted_path, path, target_encoding);
        int original_thread_mode = __ae_thread_swapmode(__AE_EBCDIC_MODE);
        ret = __stat_e(converted_path, buf); // Assuming __lstat_e exists
        saved_errno_call = errno;
        __ae_thread_swapmode(original_thread_mode);
        errno = saved_errno_call;
        free(converted_path);
        return ret;
    } else {
        trace_printf("zos_stat: ASCII path for '%s'\n", path);
        return __stat_a(path, buf); // Using standard stat
    }
#else // Not __MVS__
    trace_printf("zos_stat: ASCII path for '%s'\n", path);
    return __stat_a(path, buf);
#endif
}

// Wrapper for lstat
int zos_lstat(const char *path, struct stat *buf) {
#ifdef __MVS__
    const char *target_encoding = get_worktree_filename_encoding();
    bool isConverted = false;
    char* converted_path = NULL;
    int ret = -1;
    int saved_errno_call = 0;

    if (target_encoding && strcmp(target_encoding, "UTF-8") != 0) {
        converted_path = git_utf8_to_worktree_enc(path);
        if (!converted_path) {
            if (errno == 0) errno = EILSEQ;
            return -1;
        }
        isConverted = true;
    }

    if (isConverted) {
        trace_printf("zos_lstat: EBCDIC path for '%s' (orig: '%s') with encoding '%s'\n", converted_path, path, target_encoding);
        int original_thread_mode = __ae_thread_swapmode(__AE_EBCDIC_MODE);
        ret = __lstat_e(converted_path, buf); // Assuming __lstat_e exists
        saved_errno_call = errno;
        __ae_thread_swapmode(original_thread_mode);
        errno = saved_errno_call;
        free(converted_path);
        return ret;
    } else {
        trace_printf("zos_lstat: ASCII path for '%s'\n", path);
        return __lstat_a(path, buf); // Using standard lstat
    }
#else // Not __MVS__
    trace_printf("zos_lstat: ASCII path for '%s'\n", path);
    return __lstat_a(path, buf);
#endif
}

// Wrapper for fopen
FILE *zos_fopen(const char *path, const char *mode) {
#ifdef __MVS__
    const char *target_encoding = get_worktree_filename_encoding();
    bool isConverted = false;
    char* converted_path = NULL;
    char* converted_mode = NULL;
    FILE *fp = NULL;
    int saved_errno_call = 0;

    if (target_encoding && strcmp(target_encoding, "UTF-8") != 0) {
        converted_path = git_utf8_to_worktree_enc(path);
        if (!converted_path) {
            if (errno == 0) errno = EILSEQ;
            return NULL;
        }
        // Mode string also needs conversion.
        converted_mode = git_utf8_to_worktree_enc(mode);
        if (!converted_mode) {
            if (errno == 0) errno = EILSEQ;
            free(converted_path);
            return NULL;
        }
        isConverted = true;
    }

    if (isConverted) {
        trace_printf("zos_fopen: EBCDIC path for '%s' (orig: '%s'), mode '%s' (orig: '%s') with encoding '%s'\n",
                     converted_path, path, converted_mode, mode, target_encoding);
        int original_thread_mode = __ae_thread_swapmode(__AE_EBCDIC_MODE);
        fp = __fopen_e(converted_path, converted_mode); // Assuming __fopen_e exists
        saved_errno_call = errno;
        __ae_thread_swapmode(original_thread_mode);
        errno = saved_errno_call;
        free(converted_path);
        free(converted_mode);
        return fp;
    } else {
        trace_printf("zos_fopen: ASCII path for '%s', mode '%s'\n", path, mode);
        return __fopen_ascii(path, mode); // Using standard fopen
    }
#else // Not __MVS__
    return __fopen_ascii(path, mode);
#endif
}

// Wrapper for unlink
int zos_unlink(const char *path) {
#ifdef __MVS__
    const char *target_encoding = get_worktree_filename_encoding();
    bool isConverted = false;
    char* converted_path = NULL;
    int ret = -1;
    int saved_errno_call = 0;

    if (target_encoding && strcmp(target_encoding, "UTF-8") != 0) {
        converted_path = git_utf8_to_worktree_enc(path);
        if (!converted_path) {
            if (errno == 0) errno = EILSEQ;
            return -1;
        }
        isConverted = true;
    }

    if (isConverted) {
        trace_printf("zos_unlink: EBCDIC path for '%s' (orig: '%s') with encoding '%s'\n", converted_path, path, target_encoding);
        int original_thread_mode = __ae_thread_swapmode(__AE_EBCDIC_MODE);
        ret = __unlink_e(converted_path); // Assuming __unlink_e exists
        saved_errno_call = errno;
        __ae_thread_swapmode(original_thread_mode);
        errno = saved_errno_call;
        free(converted_path);
        return ret;
    } else {
        trace_printf("zos_unlink: ASCII path for '%s'\n", path);
        return __unlink_a(path); // Using standard unlink
    }
#else // Not __MVS__
    return __unlink_a(path);
#endif
}

// Wrapper for rmdir
int zos_rmdir(const char *path) {
#ifdef __MVS__
    const char *target_encoding = get_worktree_filename_encoding();
    bool isConverted = false;
    char* converted_path = NULL;
    int ret = -1;
    int saved_errno_call = 0;

    if (target_encoding && strcmp(target_encoding, "UTF-8") != 0) {
        converted_path = git_utf8_to_worktree_enc(path);
        if (!converted_path) {
            if (errno == 0) errno = EILSEQ;
            return -1;
        }
        isConverted = true;
    }

    if (isConverted) {
        trace_printf("zos_rmdir: EBCDIC path for '%s' (orig: '%s') with encoding '%s'\n", converted_path, path, target_encoding);
        int original_thread_mode = __ae_thread_swapmode(__AE_EBCDIC_MODE);
        ret = __rmdir_e(converted_path); // Assuming __rmdir_e exists
        saved_errno_call = errno;
        __ae_thread_swapmode(original_thread_mode);
        errno = saved_errno_call;
        free(converted_path);
        return ret;
    } else {
        trace_printf("zos_rmdir: ASCII path for '%s'\n", path);
        return __rmdir_a(path); // Using standard rmdir
    }
#else // Not __MVS__
    return __rmdir_a(path);
#endif
}

// Wrapper for mkdir
int zos_mkdir(const char *path, mode_t mode) {
#if 0 //def __MVS__
    const char *target_encoding = get_worktree_filename_encoding();
    bool isConverted = false;
    char* converted_path = NULL;
    int ret = -1;
    int saved_errno_call = 0;

    if (target_encoding && strcmp(target_encoding, "UTF-8") != 0) {
        converted_path = git_utf8_to_worktree_enc(path);
        if (!converted_path) {
            if (errno == 0) errno = EILSEQ;
            return -1;
        }
        isConverted = true;
    }

    if (isConverted) {
        trace_printf("zos_mkdir: EBCDIC path for '%s' (orig: '%s') with encoding '%s'\n", converted_path, path, target_encoding);
        int original_thread_mode = __ae_thread_swapmode(__AE_EBCDIC_MODE);
        ret = __mkdir_e(converted_path, mode); // Assuming __mkdir_e exists
        saved_errno_call = errno;
        __ae_thread_swapmode(original_thread_mode);
        errno = saved_errno_call;
        free(converted_path);
        return ret;
    } else {
        trace_printf("zos_mkdir: ASCII path for '%s'\n", path);
        return __mkdir_a(path, mode); // Using standard mkdir
    }
#else // Not __MVS__
    trace_printf("zos_mkdir: ASCII path for '%s'\n", path);
    return __mkdir_a(path, mode);
#endif
}

// Wrapper for rename
int zos_rename(const char *oldpath, const char *newpath) {
#ifdef __MVS__
    const char *target_encoding = get_worktree_filename_encoding();
    bool isConverted = false;
    char* converted_oldpath = NULL;
    char* converted_newpath = NULL;
    int ret = -1;
    int saved_errno_call = 0;

    if (target_encoding && strcmp(target_encoding, "UTF-8") != 0) {
        converted_oldpath = git_utf8_to_worktree_enc(oldpath);
        if (!converted_oldpath) {
            if (errno == 0) errno = EILSEQ;
            return -1;
        }
        converted_newpath = git_utf8_to_worktree_enc(newpath);
        if (!converted_newpath) {
            if (errno == 0) errno = EILSEQ;
            free(converted_oldpath);
            return -1;
        }
        isConverted = true;
    }

    if (isConverted) {
        trace_printf("zos_rename: EBCDIC oldpath '%s' (orig: '%s'), newpath '%s' (orig: '%s') with encoding '%s'\n",
                     converted_oldpath, oldpath, converted_newpath, newpath, target_encoding);
        int original_thread_mode = __ae_thread_swapmode(__AE_EBCDIC_MODE);
        ret = __rename_e(converted_oldpath, converted_newpath); // Assuming __rename_e exists
        saved_errno_call = errno;
        __ae_thread_swapmode(original_thread_mode);
        errno = saved_errno_call;
        free(converted_oldpath);
        free(converted_newpath);
        return ret;
    } else {
        trace_printf("zos_rename: ASCII oldpath '%s', newpath '%s'\n", oldpath, newpath);
        return __rename_a(oldpath, newpath); // Using standard rename
    }
#else // Not __MVS__
    return __rename_a(oldpath, newpath);
#endif
}

// Wrapper for readlink
ssize_t zos_readlink(const char *path, char *buf, size_t bufsize) {
#ifdef __MVS__
    const char *target_encoding = get_worktree_filename_encoding();
    bool isConverted = false;
    char* converted_path = NULL;
    ssize_t ret = -1;
    int saved_errno_call = 0;
    char *ebcdic_link_content_buf = NULL; // Buffer for EBCDIC link content

    if (target_encoding && strcmp(target_encoding, "UTF-8") != 0) {
        converted_path = git_utf8_to_worktree_enc(path);
        if (!converted_path) {
            if (errno == 0) errno = EILSEQ;
            return -1;
        }
        ebcdic_link_content_buf = xmalloc(bufsize); 
        isConverted = true;
    }

    if (isConverted) {
        trace_printf("zos_readlink: EBCDIC path for '%s' (orig: '%s') with encoding '%s'\n", converted_path, path, target_encoding);
        int original_thread_mode = __ae_thread_swapmode(__AE_EBCDIC_MODE);
        ret = __readlink_e(converted_path, ebcdic_link_content_buf, bufsize -1); 
        saved_errno_call = errno;
        __ae_thread_swapmode(original_thread_mode);
        errno = saved_errno_call;
        free(converted_path);

        if (ret > 0) {
            ebcdic_link_content_buf[ret] = '\0'; 
            char *utf8_link_content = git_worktree_enc_to_utf8(ebcdic_link_content_buf);
            if (utf8_link_content) {
                strlcpy(buf, utf8_link_content, bufsize);
                buf[bufsize - 1] = '\0'; 
                ret = strlen(buf); 
                free(utf8_link_content);
            } else {
                if (errno == 0) errno = EILSEQ; 
                ret = -1; 
            }
        }
        free(ebcdic_link_content_buf); // Free even if git_worktree_enc_to_utf8 failed or ret <=0
        return ret;
    } else {
        trace_printf("zos_readlink: ASCII path for '%s'\n", path);
        return __readlink(path, buf, bufsize); 
    }
#else // Not __MVS__
    return __readlink(path, buf, bufsize);
#endif
}

// Wrapper for symlink
int zos_symlink(const char *target, const char *linkpath) {
#ifdef __MVS__
    const char *target_encoding = get_worktree_filename_encoding();
    bool isConverted = false;
    char* converted_target = NULL;   
    char* converted_linkpath = NULL; 
    int ret = -1;
    int saved_errno_call = 0;

    if (target_encoding && strcmp(target_encoding, "UTF-8") != 0) {
        converted_linkpath = git_utf8_to_worktree_enc(linkpath);
        if (!converted_linkpath) {
            if (errno == 0) errno = EILSEQ;
            return -1;
        }
        converted_target = git_utf8_to_worktree_enc(target);
        if (!converted_target) {
            if (errno == 0) errno = EILSEQ;
            free(converted_linkpath);
            return -1;
        }
        isConverted = true;
    }

    if (isConverted) {
        trace_printf("zos_symlink: EBCDIC target '%s' (orig: '%s'), linkpath '%s' (orig: '%s') with encoding '%s'\n",
                     converted_target, target, converted_linkpath, linkpath, target_encoding);
        int original_thread_mode = __ae_thread_swapmode(__AE_EBCDIC_MODE);
        ret = __symlink_e(converted_target, converted_linkpath); 
        saved_errno_call = errno;
        __ae_thread_swapmode(original_thread_mode);
        errno = saved_errno_call;
        free(converted_target);
        free(converted_linkpath);
        return ret;
    } else {
        trace_printf("zos_symlink: ASCII target '%s', linkpath '%s'\n", target, linkpath);
        return __symlink_a(target, linkpath); 
    }
#else // Not __MVS__
    return __symlink_a(target, linkpath);
#endif
}

// Wrapper for opendir
DIR *zos_opendir(const char *name) {
#ifdef __MVS__
    const char *target_encoding = get_worktree_filename_encoding();
    bool isConverted = false;
    char* converted_name = NULL;
    DIR *dirp = NULL;
    int saved_errno_call = 0;

    if (target_encoding && strcmp(target_encoding, "UTF-8") != 0) {
        converted_name = git_utf8_to_worktree_enc(name);
        if (!converted_name) {
            if (errno == 0) errno = EILSEQ;
            return NULL;
        }
        isConverted = true;
    }

    if (isConverted) {
        trace_printf("zos_opendir: EBCDIC path for '%s' (orig: '%s') with encoding '%s'\n", converted_name, name, target_encoding);
        int original_thread_mode = __ae_thread_swapmode(__AE_EBCDIC_MODE);
        dirp = __opendir_e(converted_name); 
        saved_errno_call = errno;
        __ae_thread_swapmode(original_thread_mode);
        errno = saved_errno_call;
        free(converted_name);
        return dirp;
    } else {
        trace_printf("zos_opendir: ASCII path for '%s'\n", name);
        return __opendir_e(name); 
    }
#else // Not __MVS__
    return __opendir_a(name);
#endif
}



int zos_chmod(const char *path, mode_t mode) {
#ifdef __MVS__
    const char *target_encoding = get_worktree_filename_encoding();
    char* converted_path = NULL;
    int ret = -1;
    int saved_errno_call = 0;

    if (target_encoding && strcmp(target_encoding, "UTF-8") != 0) {
        converted_path = git_utf8_to_worktree_enc(path);
        if (!converted_path) {
            if (errno == 0) errno = EILSEQ;
            return -1;
        }
        trace_printf("zos_chmod: EBCDIC path for '%s' (orig: '%s') with encoding '%s'\n", converted_path, path, target_encoding);
        int original_thread_mode = __ae_thread_swapmode(__AE_EBCDIC_MODE);
        ret = __chmod_e(converted_path, mode);
        saved_errno_call = errno;
        __ae_thread_swapmode(original_thread_mode);
        errno = saved_errno_call;
        free(converted_path);
        return ret;
    } else {
        trace_printf("zos_chmod: ASCII path for '%s'\n", path);
        return __chmod_a(path, mode);
    }
#else // Not __MVS__
    return chmod(path, mode);
#endif
}

int zos_utime(const char *path, const struct utimbuf *times) {
#ifdef __MVS__
    const char *target_encoding = get_worktree_filename_encoding();
    char* converted_path = NULL;
    int ret = -1;
    int saved_errno_call = 0;

    if (target_encoding && strcmp(target_encoding, "UTF-8") != 0) {
        converted_path = git_utf8_to_worktree_enc(path);
        if (!converted_path) {
            if (errno == 0) errno = EILSEQ;
            return -1;
        }
        trace_printf("zos_utime: EBCDIC path for '%s' (orig: '%s') with encoding '%s'\n", converted_path, path, target_encoding);
        int original_thread_mode = __ae_thread_swapmode(__AE_EBCDIC_MODE);
        ret = __utime_e(converted_path, times);
        saved_errno_call = errno;
        __ae_thread_swapmode(original_thread_mode);
        errno = saved_errno_call;
        free(converted_path);
        return ret;
    } else {
        trace_printf("zos_utime: ASCII path for '%s'\n", path);
        return __utime_a(path, times);
    }
#else // Not __MVS__
    return utime(path, times);
#endif
}
#endif

static void create_directories(const char *path, int path_len,
			       const struct checkout *state)
{

	char *buf = xmallocz(path_len);
	int len = 0;

	while (len < path_len) {
		do {
			buf[len] = path[len];
			len++;
		} while (len < path_len && path[len] != '/');
		if (len >= path_len)
			break;
		buf[len] = 0;

		/*
		 * For 'checkout-index --prefix=<dir>', <dir> is
		 * allowed to be a symlink to an existing directory,
		 * and we set 'state->base_dir_len' below, such that
		 * we test the path components of the prefix with the
		 * stat() function instead of the lstat() function.
		 */
		if (has_dirs_only_path(buf, len, state->base_dir_len))
			continue; /* ok, it is already a directory. */

		/*
		 * If this mkdir() would fail, it could be that there
		 * is already a symlink or something else exists
		 * there, therefore we then try to unlink it and try
		 * one more time to create the directory.
		 */
		if (mkdir(buf, 0777)) {
			if (errno == EEXIST && state->force &&
			    !unlink_or_warn(buf) && !mkdir(buf, 0777))
				continue;
			die_errno("cannot create directory at '%s'", buf);
		}
	}
	free(buf);
}

static void remove_subtree(struct strbuf *path)
{
	DIR *dir = opendir(path->buf);
	struct dirent *de;
	int origlen = path->len;

	if (!dir)
		die_errno("cannot opendir '%s'", path->buf);
	while ((de = readdir_skip_dot_and_dotdot(dir)) != NULL) {
		struct stat st;

		strbuf_addch(path, '/');
		strbuf_addstr(path, de->d_name);
		if (lstat(path->buf, &st))
			die_errno("cannot lstat '%s'", path->buf);
		if (S_ISDIR(st.st_mode))
			remove_subtree(path);
		else if (unlink(path->buf))
			die_errno("cannot unlink '%s'", path->buf);
		strbuf_setlen(path, origlen);
	}
	closedir(dir);
	if (rmdir(path->buf))
		die_errno("cannot rmdir '%s'", path->buf);
}

static int create_file(const char *path, unsigned int mode)
{
	mode = (mode & 0100) ? 0777 : 0666;
	return open(path, O_WRONLY | O_CREAT | O_EXCL, mode);
}




void *read_blob_entry(const struct cache_entry *ce, size_t *size)
{
	enum object_type type;
	unsigned long ul;
	void *blob_data = repo_read_object_file(the_repository, &ce->oid,
						&type, &ul);

	*size = ul;
	if (blob_data) {
		if (type == OBJ_BLOB)
			return blob_data;
		free(blob_data);
	}
	return NULL;
}

static int open_output_fd(char *path, const struct cache_entry *ce, int to_tempfile)
{
	int symlink = (ce->ce_mode & S_IFMT) != S_IFREG;
	if (to_tempfile) {
		xsnprintf(path, TEMPORARY_FILENAME_LENGTH, "%s",
			  symlink ? ".merge_link_XXXXXX" : ".merge_file_XXXXXX");
		return mkstemp(path);
	} else {
		return create_file(path, !symlink ? ce->ce_mode : 0666);
	}
}

int fstat_checkout_output(int fd, const struct checkout *state, struct stat *st)
{
	/* use fstat() only when path == ce->name */
	if (fstat_is_reliable() &&
	    state->refresh_cache && !state->base_dir_len) {
		return !fstat(fd, st);
	}
	return 0;
}

#ifdef __MVS__
void tag_file_as_working_tree_encoding(struct index_state *istate, char* path, int fd) {
	struct conv_attrs ca;
	convert_attrs(istate, &ca, path);
  if (ca.attr_action != CRLF_BINARY) {
    if (ca.working_tree_encoding)
      __chgfdcodeset(fd, ca.working_tree_encoding); 
    else
      __chgfdccsid(fd, utf8_ccsid);
  }
  else {
    __setfdbinary(fd);
  }

  __disableautocvt(fd);
}
#endif

static int streaming_write_entry(const struct cache_entry *ce, char *path,
				 struct stream_filter *filter,
				 const struct checkout *state, int to_tempfile,
				 int *fstat_done, struct stat *statbuf)
{
	int result = 0;
	int fd;

	fd = open_output_fd(path, ce, to_tempfile);
	if (fd < 0)
		return -1;

#ifdef __MVS__
  tag_file_as_working_tree_encoding(state->istate, path, fd);
#endif

	result |= stream_blob_to_fd(fd, &ce->oid, filter, 1);
	*fstat_done = fstat_checkout_output(fd, state, statbuf);
	result |= close(fd);

	if (result)
		unlink(path);
	return result;
}

void enable_delayed_checkout(struct checkout *state)
{
	if (!state->delayed_checkout) {
		state->delayed_checkout = xmalloc(sizeof(*state->delayed_checkout));
		state->delayed_checkout->state = CE_CAN_DELAY;
		string_list_init_nodup(&state->delayed_checkout->filters);
		string_list_init_nodup(&state->delayed_checkout->paths);
	}
}

static int remove_available_paths(struct string_list_item *item, void *cb_data)
{
	struct string_list *available_paths = cb_data;
	struct string_list_item *available;

	available = string_list_lookup(available_paths, item->string);
	if (available)
		available->util = item->util;
	return !available;
}

static int string_is_not_null(struct string_list_item *item, void *data UNUSED)
{
	return !!item->string;
}

int finish_delayed_checkout(struct checkout *state, int show_progress)
{
	int errs = 0;
	unsigned processed_paths = 0;
	off_t filtered_bytes = 0;
	struct string_list_item *filter, *path;
	struct progress *progress = NULL;
	struct delayed_checkout *dco = state->delayed_checkout;

	if (!state->delayed_checkout)
		return errs;

	dco->state = CE_RETRY;
	if (show_progress)
		progress = start_delayed_progress(the_repository,
						  _("Filtering content"),
						  dco->paths.nr);
	while (dco->filters.nr > 0) {
		for_each_string_list_item(filter, &dco->filters) {
			struct string_list available_paths = STRING_LIST_INIT_DUP;

			if (!async_query_available_blobs(filter->string, &available_paths)) {
				/* Filter reported an error */
				errs = 1;
				filter->string = NULL;
				continue;
			}
			if (available_paths.nr <= 0) {
				/*
				 * Filter responded with no entries. That means
				 * the filter is done and we can remove the
				 * filter from the list (see
				 * "string_list_remove_empty_items" call below).
				 */
				filter->string = NULL;
				continue;
			}

			/*
			 * In dco->paths we store a list of all delayed paths.
			 * The filter just send us a list of available paths.
			 * Remove them from the list.
			 */
			filter_string_list(&dco->paths, 0,
				&remove_available_paths, &available_paths);

			for_each_string_list_item(path, &available_paths) {
				struct cache_entry* ce;

				if (!path->util) {
					error("external filter '%s' signaled that '%s' "
					      "is now available although it has not been "
					      "delayed earlier",
					      filter->string, path->string);
					errs |= 1;

					/*
					 * Do not ask the filter for available blobs,
					 * again, as the filter is likely buggy.
					 */
					filter->string = NULL;
					continue;
				}
				ce = index_file_exists(state->istate, path->string,
						       strlen(path->string), 0);
				if (ce) {
					display_progress(progress, ++processed_paths);
					errs |= checkout_entry(ce, state, NULL, path->util);
					filtered_bytes += ce->ce_stat_data.sd_size;
					display_throughput(progress, filtered_bytes);
				} else
					errs = 1;
			}

			string_list_clear(&available_paths, 0);
		}

		filter_string_list(&dco->filters, 0, string_is_not_null, NULL);
	}
	stop_progress(&progress);
	string_list_clear(&dco->filters, 0);

	/* At this point we should not have any delayed paths anymore. */
	errs |= dco->paths.nr;
	for_each_string_list_item(path, &dco->paths) {
		error("'%s' was not filtered properly", path->string);
	}
	string_list_clear(&dco->paths, 0);

	free(dco);
	state->delayed_checkout = NULL;

	return errs;
}

void update_ce_after_write(const struct checkout *state, struct cache_entry *ce,
			   struct stat *st)
{
	if (state->refresh_cache) {
		assert(state->istate);
		fill_stat_cache_info(state->istate, ce, st);
		ce->ce_flags |= CE_UPDATE_IN_BASE;
		mark_fsmonitor_invalid(state->istate, ce);
		state->istate->cache_changed |= CE_ENTRY_CHANGED;
	}
}

/* Note: ca is used (and required) iff the entry refers to a regular file. */
static int write_entry(struct cache_entry *ce, char *path, struct conv_attrs *ca,
		       const struct checkout *state, int to_tempfile,
		       int *nr_checkouts)
{
	unsigned int ce_mode_s_ifmt = ce->ce_mode & S_IFMT;
	struct delayed_checkout *dco = state->delayed_checkout;
	int fd, ret, fstat_done = 0;
	char *new_blob;
	struct strbuf buf = STRBUF_INIT;
	size_t size;
	ssize_t wrote;
	size_t newsize = 0;
	struct stat st;
	const struct submodule *sub;
	struct checkout_metadata meta;
	static int scratch_nr_checkouts;

	clone_checkout_metadata(&meta, &state->meta, &ce->oid);

	if (ce_mode_s_ifmt == S_IFREG) {
		struct stream_filter *filter = get_stream_filter_ca(ca, &ce->oid);
		if (filter &&
		    !streaming_write_entry(ce, path, filter,
					   state, to_tempfile,
					   &fstat_done, &st))
			goto finish;
	}

	switch (ce_mode_s_ifmt) {
	case S_IFLNK:
		new_blob = read_blob_entry(ce, &size);
		if (!new_blob)
			return error("unable to read sha1 file of %s (%s)",
				     ce->name, oid_to_hex(&ce->oid));

		/*
		 * We can't make a real symlink; write out a regular file entry
		 * with the symlink destination as its contents.
		 */
		if (!has_symlinks || to_tempfile)
			goto write_file_entry;

		ret = symlink(new_blob, path);
		free(new_blob);
		if (ret)
			return error_errno("unable to create symlink %s", path);
		break;

	case S_IFREG:
		/*
		 * We do not send the blob in case of a retry, so do not
		 * bother reading it at all.
		 */
		if (dco && dco->state == CE_RETRY) {
			new_blob = NULL;
			size = 0;
		} else {
			new_blob = read_blob_entry(ce, &size);
			if (!new_blob)
				return error("unable to read sha1 file of %s (%s)",
					     ce->name, oid_to_hex(&ce->oid));
		}

		/*
		 * Convert from git internal format to working tree format
		 */
		if (dco && dco->state != CE_NO_DELAY) {
			ret = async_convert_to_working_tree_ca(ca, ce->name,
							       new_blob, size,
							       &buf, &meta, dco);
			if (ret) {
				struct string_list_item *item =
					string_list_lookup(&dco->paths, ce->name);
				if (item) {
					item->util = nr_checkouts ? nr_checkouts
							: &scratch_nr_checkouts;
					free(new_blob);
					goto delayed;
				}
			}
		} else {
			ret = convert_to_working_tree_ca(ca, ce->name, new_blob,
							 size, &buf, &meta);
		}

		if (ret) {
			free(new_blob);
			new_blob = strbuf_detach(&buf, &newsize);
			size = newsize;
		}
		/*
		 * No "else" here as errors from convert are OK at this
		 * point. If the error would have been fatal (e.g.
		 * filter is required), then we would have died already.
		 */

	write_file_entry:
		fd = open_output_fd(path, ce, to_tempfile);
		if (fd < 0) {
			free(new_blob);
			return error_errno("unable to create file %s", path);
		}

#ifdef __MVS__
    tag_file_as_working_tree_encoding(state->istate, path, fd);
#endif

		wrote = write_in_full(fd, new_blob, size);
		if (!to_tempfile)
			fstat_done = fstat_checkout_output(fd, state, &st);
		close(fd);
		free(new_blob);
		if (wrote < 0)
			return error("unable to write file %s", path);
		break;

	case S_IFGITLINK:
		if (to_tempfile)
			return error("cannot create temporary submodule %s", ce->name);
		if (mkdir(path, 0777) < 0)
			return error("cannot create submodule directory %s", path);
		sub = submodule_from_ce(ce);
		if (sub)
			return submodule_move_head(ce->name, state->super_prefix,
				NULL, oid_to_hex(&ce->oid),
				state->force ? SUBMODULE_MOVE_HEAD_FORCE : 0);
		break;

	default:
		return error("unknown file mode for %s in index", ce->name);
	}

finish:
	if (state->refresh_cache) {
		if (!fstat_done && lstat(ce->name, &st) < 0)
			return error_errno("unable to stat just-written file %s",
					   ce->name);
		update_ce_after_write(state, ce , &st);
	}
	if (nr_checkouts)
		(*nr_checkouts)++;
delayed:
	return 0;
}

/*
 * This is like 'lstat()', except it refuses to follow symlinks
 * in the path, after skipping "skiplen".
 */
static int check_path(const char *path, int len, struct stat *st, int skiplen)
{
	const char *slash = path + len;

	while (path < slash && *slash != '/')
		slash--;
	if (!has_dirs_only_path(path, slash - path, skiplen)) {
		errno = ENOENT;
		return -1;
	}
	return lstat(path, st);
}

static void mark_colliding_entries(const struct checkout *state,
				   struct cache_entry *ce, struct stat *st)
{
	int trust_ino = check_stat;

#if defined(GIT_WINDOWS_NATIVE) || defined(__CYGWIN__)
	trust_ino = 0;
#endif

	ce->ce_flags |= CE_MATCHED;

	/* TODO: audit for interaction with sparse-index. */
	ensure_full_index(state->istate);
	for (size_t i = 0; i < state->istate->cache_nr; i++) {
		struct cache_entry *dup = state->istate->cache[i];

		if (dup == ce) {
			/*
			 * Parallel checkout doesn't create the files in index
			 * order. So the other side of the collision may appear
			 * after the given cache_entry in the array.
			 */
			if (parallel_checkout_status() == PC_RUNNING)
				continue;
			else
				break;
		}

		if (dup->ce_flags & (CE_MATCHED | CE_VALID | CE_SKIP_WORKTREE))
			continue;

		if ((trust_ino && !match_stat_data(&dup->ce_stat_data, st)) ||
		    paths_collide(ce->name, dup->name)) {
			dup->ce_flags |= CE_MATCHED;
			break;
		}
	}
}

int checkout_entry_ca(struct cache_entry *ce, struct conv_attrs *ca,
		      const struct checkout *state, char *topath,
		      int *nr_checkouts)
{
	static struct strbuf path = STRBUF_INIT;
	struct stat st;
	struct conv_attrs ca_buf;


#ifdef __MVS__
  const char* git_utf8_ccsid_str = getenv("GIT_UTF8_CCSID");

  if (git_utf8_ccsid_str != NULL) {
      char* endptr;
      errno = 0;
      long conv = strtol(git_utf8_ccsid_str, &endptr, 10);

      if (!conv) {
          perror("Error converting GIT_UTF8_CCSID to short");
      } else if (endptr == git_utf8_ccsid_str) {
          fprintf(stderr, "No digits were found in GIT_UTF8_CCSID\n");
      } else {
          utf8_ccsid = conv;
      }
  }
#endif

	if (ce->ce_flags & CE_WT_REMOVE) {
		if (topath)
			/*
			 * No content and thus no path to create, so we have
			 * no pathname to return.
			 */
			BUG("Can't remove entry to a path");
		unlink_entry(ce, state->super_prefix);
		return 0;
	}

	if (topath) {
		if (S_ISREG(ce->ce_mode) && !ca) {
			convert_attrs(state->istate, &ca_buf, ce->name);
			ca = &ca_buf;
		}
		return write_entry(ce, topath, ca, state, 1, nr_checkouts);
	}

	strbuf_reset(&path);
	strbuf_add(&path, state->base_dir, state->base_dir_len);
	strbuf_add(&path, ce->name, ce_namelen(ce));

	if (!check_path(path.buf, path.len, &st, state->base_dir_len)) {
		const struct submodule *sub;
		unsigned changed = ie_match_stat(state->istate, ce, &st,
						 CE_MATCH_IGNORE_VALID | CE_MATCH_IGNORE_SKIP_WORKTREE);
		/*
		 * Needs to be checked before !changed returns early,
		 * as the possibly empty directory was not changed
		 */
		sub = submodule_from_ce(ce);
		if (sub) {
			int err;
			if (!is_submodule_populated_gently(ce->name, &err)) {
				struct stat sb;
				if (lstat(ce->name, &sb))
					die(_("could not stat file '%s'"), ce->name);
				if (!(st.st_mode & S_IFDIR))
					unlink_or_warn(ce->name);

				return submodule_move_head(ce->name, state->super_prefix,
					NULL, oid_to_hex(&ce->oid), 0);
			} else
				return submodule_move_head(ce->name, state->super_prefix,
					"HEAD", oid_to_hex(&ce->oid),
					state->force ? SUBMODULE_MOVE_HEAD_FORCE : 0);
		}

		if (!changed)
			return 0;
		if (!state->force) {
			if (!state->quiet)
				fprintf(stderr,
					"%s already exists, no checkout\n",
					path.buf);
			return -1;
		}

		if (state->clone)
			mark_colliding_entries(state, ce, &st);

		/*
		 * We unlink the old file, to get the new one with the
		 * right permissions (including umask, which is nasty
		 * to emulate by hand - much easier to let the system
		 * just do the right thing)
		 */
		if (S_ISDIR(st.st_mode)) {
			/* If it is a gitlink, leave it alone! */
			if (S_ISGITLINK(ce->ce_mode))
				return 0;
			/*
			 * We must avoid replacing submodules' leading
			 * directories with symbolic links, lest recursive
			 * clones can write into arbitrary locations.
			 *
			 * Technically, this logic is not limited
			 * to recursive clones, or for that matter to
			 * submodules' paths colliding with symbolic links'
			 * paths. Yet it strikes a balance in favor of
			 * simplicity, and if paths are colliding, we might
			 * just as well keep the directories during a clone.
			 */
			if (state->clone && S_ISLNK(ce->ce_mode))
				return 0;
			remove_subtree(&path);
		} else if (unlink(path.buf))
			return error_errno("unable to unlink old '%s'", path.buf);
	} else if (state->not_new)
		return 0;

	create_directories(path.buf, path.len, state);

	if (S_ISREG(ce->ce_mode) && !ca) {
		convert_attrs(state->istate, &ca_buf, ce->name);
		ca = &ca_buf;
	}

	if (!enqueue_checkout(ce, ca, nr_checkouts))
		return 0;

	return write_entry(ce, path.buf, ca, state, 0, nr_checkouts);
}

void unlink_entry(const struct cache_entry *ce, const char *super_prefix)
{
	const struct submodule *sub = submodule_from_ce(ce);
	if (sub) {
		/* state.force is set at the caller. */
		submodule_move_head(ce->name, super_prefix, "HEAD", NULL,
				    SUBMODULE_MOVE_HEAD_FORCE);
	}
	if (check_leading_path(ce->name, ce_namelen(ce), 1) >= 0)
		return;
	if (remove_or_warn(ce->ce_mode, ce->name))
		return;
	schedule_dir_for_removal(ce->name, ce_namelen(ce));
}

int remove_or_warn(unsigned int mode, const char *file)
{
	return S_ISGITLINK(mode) ? rmdir_or_warn(file) : unlink_or_warn(file);
}
