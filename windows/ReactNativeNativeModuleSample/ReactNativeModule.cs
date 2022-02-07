using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Reactive.Disposables;
using System.Security.Cryptography;
using System.IO;
using System.Net.Http;

using Microsoft.ReactNative;
using Microsoft.ReactNative.Managed;
using Syroot.Windows.IO;

namespace ReactNativeNativeModuleSample
{
    /// <summary>
    /// Task cancellation manager.
    /// </summary>
    /// <typeparam name="TKey">Type of key used to identify tasks.</typeparam>
    class TaskCancellationManager<TKey>
    {
        private readonly object _gate = new object();
        private readonly IDictionary<TKey, IDisposable> _tokens;

        /// <summary>
        /// Instantiates a <see cref="TaskCancellationManager{TKey}"/>.
        /// </summary>
        public TaskCancellationManager()
            : this(EqualityComparer<TKey>.Default)
        {
        }

        /// <summary>
        /// Instantiates a <see cref="TaskCancellationManager{TKey}"/>.
        /// </summary>
        /// <param name="keyComparer">The key comparer.</param>
        public TaskCancellationManager(IEqualityComparer<TKey> keyComparer)
        {
            if (keyComparer == null)
                throw new ArgumentNullException(nameof(keyComparer));

            _tokens = new Dictionary<TKey, IDisposable>(keyComparer);
        }

        /// <summary>
        /// Number of outstanding operations being managed.
        /// </summary>
        internal int PendingOperationCount
        {
            get
            {
                return _tokens.Count;
            }
        }

        /// <summary>
        /// Adds a task to the manager.
        /// </summary>
        /// <param name="key">The task key.</param>
        /// <param name="taskFactory">The task factory.</param>
        /// <remarks>
        /// The task factory is invoked during this method call.
        /// </remarks>
        public Task AddAndInvokeAsync(TKey key, Func<CancellationToken, Task> taskFactory)
        {
            var disposable = new CancellationDisposable();
            lock (_gate)
            {
                _tokens.Add(key, disposable);
            }

            return taskFactory(disposable.Token).ContinueWith(
                task =>
                {
                    lock (_gate)
                    {
                        _tokens.Remove(key);
                    }

                    disposable.Dispose();
                    return task;
                },
                TaskContinuationOptions.ExecuteSynchronously).Unwrap();
        }

        /// <summary>
        /// Cancels the task with the given key.
        /// </summary>
        /// <param name="key">The task key.</param>
        public void Cancel(TKey key)
        {
            IDisposable disposable;
            lock (_gate)
            {
                _tokens.TryGetValue(key, out disposable);
            }

            disposable?.Dispose();
        }

        /// <summary>
        /// Cancels all pending tasks.
        /// </summary>
        public void CancelAllTasks()
        {
            IList<IDisposable> tokens;
            lock (_gate)
            {
                // Clone the list of disposables
                tokens = _tokens.Values.ToList();
            }

            foreach (var token in tokens)
            {
                // Dispose on CancellationDisposable is idempotent
                token.Dispose();
            }
        }
    }


    [ReactModule("ReactNativeFs")]
    internal sealed class ReactNativeModule
    {
        // See https://microsoft.github.io/react-native-windows/docs/native-modules for details on writing native modules

        private ReactContext _reactContext;

        [ReactInitializer]
        public void Initialize(ReactContext reactContext)
        {
            _reactContext = reactContext;
        }

        [ReactMethod]
        public void sampleMethod(string stringArgument, int numberArgument, Action<string> callback)
        {
            // TODO: Implement some actually useful functionality
            callback("Received numberArgument: " + numberArgument + " stringArgument: " + stringArgument);
        }


        private const int FileType = 0;
        private const int DirectoryType = 1;

        private static readonly IReadOnlyDictionary<string, Func<HashAlgorithm>> s_hashAlgorithms =
            new Dictionary<string, Func<HashAlgorithm>>
            {
                { "md5", () => MD5.Create() },
                { "sha1", () => SHA1.Create() },
                { "sha256", () => SHA256.Create() },
                { "sha384", () => SHA384.Create() },
                { "sha512", () => SHA512.Create() },
            };

        private readonly TaskCancellationManager<int> _tasks = new TaskCancellationManager<int>();
        private readonly HttpClient _httpClient = new HttpClient();

        /*private RCTNativeAppEventEmitter _emitter;

        internal RCTNativeAppEventEmitter Emitter
        {
            get
            {
                if (_emitter == null)
                {
                    return Context.GetJavaScriptModule<RCTNativeAppEventEmitter>();
                }

                return _emitter;
            }
            set
            {
                _emitter = value;
            }
        }*/

        // [Obsolete]
        [ReactConstant]
        public IReadOnlyDictionary<string, object> Constants
        {
            get
            {
                var constants = new Dictionary<string, object>
                {
                    { "RNFSMainBundlePath", AppDomain.CurrentDomain.BaseDirectory },
                    { "RNFSCachesDirectoryPath", KnownFolders.Downloads.Path },
                    { "RNFSRoamingDirectoryPath", KnownFolders.RoamingAppData.Path },
                    { "RNFSDocumentDirectoryPath",  KnownFolders.Documents.Path },
                    { "RNFSTemporaryDirectoryPath", KnownFolders.InternetCache.Path },
                    { "RNFSPicturesDirectoryPath", KnownFolders.CameraRoll.Path },
                    { "RNFSFileTypeRegular", 0 },
                    { "RNFSFileTypeDirectory", 1 },
                };

                return constants;
            }
        }

        [ReactMethod]
        public async void writeFile(string filepath, string base64Content, JSValueObject options, ReactPromise<JSValue> promise)
        {
            try
            {
                // TODO: open file on background thread?
                using (var file = File.OpenWrite(filepath))
                {
                    var data = Convert.FromBase64String(base64Content);
                    await file.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
                }

                promise.Resolve(JSValue.Null);
            }
            catch (Exception ex)
            {
                Reject(promise, filepath, ex);
            }
        }

        [ReactMethod]
        public async void appendFile(string filepath, string base64Content, ReactPromise<JSValue> promise)
        {
            try
            {
                // TODO: open file on background thread?
                using (var file = File.Open(filepath, FileMode.Append))
                {
                    var data = Convert.FromBase64String(base64Content);
                    await file.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
                }

                promise.Resolve(JSValue.Null);
            }
            catch (Exception ex)
            {
                Reject(promise, filepath, ex);
            }
        }

        [ReactMethod]
        public async void write(string filepath, string base64Content, int position, ReactPromise<JSValue> promise)
        {
            try
            {
                // TODO: open file on background thread?
                using (var file = File.OpenWrite(filepath))
                {
                    if (position >= 0)
                    {
                        file.Position = position;
                    }

                    var data = Convert.FromBase64String(base64Content);
                    await file.WriteAsync(data, 0, data.Length).ConfigureAwait(false);
                }

                promise.Resolve(JSValue.Null);
            }
            catch (Exception ex)
            {
                Reject(promise, filepath, ex);
            }
        }

        [ReactMethod]
        public void exists(string filepath, ReactPromise<JSValue> promise)
        {
            try
            {
                promise.Resolve(File.Exists(filepath) || Directory.Exists(filepath));
            }
            catch (Exception ex)
            {
                Reject(promise, filepath, ex);
            }
        }

        [ReactMethod]
        public async void readFile(string filepath, ReactPromise<JSValue> promise)
        {
            try
            {
                if (!File.Exists(filepath))
                {
                    RejectFileNotFound(promise, filepath);
                    return;
                }

                // TODO: open file on background thread?
                string base64Content;
                using (var file = File.OpenRead(filepath))
                {
                    var length = (int)file.Length;
                    var buffer = new byte[length];
                    await file.ReadAsync(buffer, 0, length).ConfigureAwait(false);
                    base64Content = Convert.ToBase64String(buffer);
                }

                promise.Resolve(base64Content);
            }
            catch (Exception ex)
            {
                Reject(promise, filepath, ex);
            }
        }

        [ReactMethod]
        public async void read(string filepath, int length, int position, ReactPromise<JSValue> promise)
        {
            try
            {
                if (!File.Exists(filepath))
                {
                    RejectFileNotFound(promise, filepath);
                    return;
                }

                // TODO: open file on background thread?
                string base64Content;
                using (var file = File.OpenRead(filepath))
                {
                    file.Position = position;
                    var buffer = new byte[length];
                    await file.ReadAsync(buffer, 0, length).ConfigureAwait(false);
                    base64Content = Convert.ToBase64String(buffer);
                }

                promise.Resolve(base64Content);
            }
            catch (Exception ex)
            {
                Reject(promise, filepath, ex);
            }
        }

        [ReactMethod]
        public async void hash(string filepath, string algorithm, ReactPromise<JSValue> promise)
        {
            var hashAlgorithmFactory = default(Func<HashAlgorithm>);
            if (!s_hashAlgorithms.TryGetValue(algorithm, out hashAlgorithmFactory))
            {
                ReactError reactError = new ReactError();
                reactError.Message = "Invalid hash algorithm";
                promise.Reject(reactError);
                return;
            }

            try
            {
                if (!File.Exists(filepath))
                {
                    RejectFileNotFound(promise, filepath);
                    return;
                }

                await Task.Run(() =>
                {
                    var hexBuilder = new StringBuilder();
                    using (var hashAlgorithm = hashAlgorithmFactory())
                    {
                        hashAlgorithm.Initialize();
                        var hash = default(byte[]);
                        using (var file = File.OpenRead(filepath))
                        {
                            hash = hashAlgorithm.ComputeHash(file);
                        }

                        foreach (var b in hash)
                        {
                            hexBuilder.Append(string.Format("{0:x2}", b));
                        }
                    }

                    promise.Resolve(hexBuilder.ToString());
                }).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                Reject(promise, filepath, ex);
            }
        }

        [ReactMethod]
        public void moveFile(string filepath, string destPath, JSValueObject options, ReactPromise<JSValue> promise)
        {
            try
            {
                // TODO: move file on background thread?
                File.Move(filepath, destPath);
                promise.Resolve(true);
            }
            catch (Exception ex)
            {
                Reject(promise, filepath, ex);
            }
        }

        [ReactMethod]
        public async void copyFile(string filepath, string destPath, JSValueObject options, ReactPromise<JSValue> promise)
        {
            try
            {
                await Task.Run(() => File.Copy(filepath, destPath)).ConfigureAwait(false);
                promise.Resolve(JSValue.Null);

            }
            catch (Exception ex)
            {
                Reject(promise, filepath, ex);
            }
        }

        [ReactMethod]
        public async void readDir(string directory, ReactPromise<JSValue> promise)
        {
            try
            {
                await Task.Run(() =>
                {
                    var info = new DirectoryInfo(directory);
                    if (!info.Exists)
                    {
                        ReactError reactError = new ReactError();
                        reactError.Message = "Folder does not exist";
                        promise.Reject(reactError);
                        return;
                    }

                    var fileMaps = new JSValueArray();
                    foreach (var item in info.EnumerateFileSystemInfos())
                    {
                        var fileMap = new JSValueObject
                        {
                            { "mtime", ConvertToUnixTimestamp(item.LastWriteTime) },
                            { "name", item.Name },
                            { "path", item.FullName },
                        };

                        var fileItem = item as FileInfo;
                        if (fileItem != null)
                        {
                            fileMap.Add("type", FileType);
                            fileMap.Add("size", fileItem.Length);
                        }
                        else
                        {
                            fileMap.Add("type", DirectoryType);
                            fileMap.Add("size", 0);
                        }

                        fileMaps.Add(fileMap);
                    }

                    promise.Resolve(fileMaps);
                });
            }
            catch (Exception ex)
            {
                Reject(promise, directory, ex);
            }
        }

        [ReactMethod]
        public void stat(string filepath, ReactPromise<JSValue> promise)
        {
            try
            {
                FileSystemInfo fileSystemInfo = new FileInfo(filepath);
                if (!fileSystemInfo.Exists)
                {
                    fileSystemInfo = new DirectoryInfo(filepath);
                    if (!fileSystemInfo.Exists)
                    {
                        ReactError reactError = new ReactError();
                        reactError.Message = "File does not exist.";
                        promise.Reject(reactError);
                        return;
                    }
                }

                var fileInfo = fileSystemInfo as FileInfo;
                var statMap = new JSValueObject
                {
                    { "ctime", ConvertToUnixTimestamp(fileSystemInfo.CreationTime) },
                    { "mtime", ConvertToUnixTimestamp(fileSystemInfo.LastWriteTime) },
                    { "size", fileInfo?.Length ?? 0 },
                    { "type", fileInfo != null ? FileType: DirectoryType },
                };

                promise.Resolve(statMap);
            }
            catch (Exception ex)
            {
                Reject(promise, filepath, ex);
            }
        }

        [ReactMethod]
        public async void unlink(string filepath, ReactPromise<JSValue> promise)
        {
            try
            {
                var directoryInfo = new DirectoryInfo(filepath);
                var fileInfo = default(FileInfo);
                if (directoryInfo.Exists)
                {
                    await Task.Run(() => Directory.Delete(filepath, true)).ConfigureAwait(false);
                }
                else if ((fileInfo = new FileInfo(filepath)).Exists)
                {
                    await Task.Run(() => File.Delete(filepath)).ConfigureAwait(false);
                }
                else
                {
                    ReactError reactError = new ReactError();
                    reactError.Message = "File does not exist.";
                    promise.Reject(reactError);
                    return;
                }

                promise.Resolve(JSValue.Null);
            }
            catch (Exception ex)
            {
                Reject(promise, filepath, ex);
            }
        }

        [ReactMethod]
        public async void mkdir(string filepath, JSValueObject options, ReactPromise<JSValue> promise)
        {
            try
            {
                await Task.Run(() => Directory.CreateDirectory(filepath)).ConfigureAwait(false);
                promise.Resolve(JSValue.Null);
            }
            catch (Exception ex)
            {
                Reject(promise, filepath, ex);
            }
        }

        [ReactMethod]
        public async void downloadFile(JSValueObject options, ReactPromise<JSValue> promise)
        {
            var filepath = (string)options["toFile"];

            try
            {
                var url = new Uri((string)options["fromUrl"]);
                var jobId = (int)options["jobId"];
                var _headers = (IReadOnlyDictionary<string, JSValue>)null;
                options["headers"].TryGetObject(out _headers);
                var headers = (JSValueObject)_headers;
                var progressDivider = (int)options["progressDivider"];

                var request = new HttpRequestMessage(HttpMethod.Get, url);
                foreach (var header in headers)
                {
                    request.Headers.Add(header.Key, header.ToString());
                }

                await _tasks.AddAndInvokeAsync(jobId, token =>
                     ProcessRequestAsync(promise, request, filepath, jobId, progressDivider, token));
            }
            catch (Exception ex)
            {
                Reject(promise, filepath, ex);
            }
        }

        [ReactMethod]
        public void stopDownload(int jobId)
        {
            _tasks.Cancel(jobId);
        }

        [ReactMethod]
        public async void getFSInfo(ReactPromise<JSValue> promise)
        {
            try
            {
                DiskStatus status = new DiskStatus();
                DiskUtil.DriveFreeBytes(KnownFolders.RoamingAppData.Path, out status);
                promise.Resolve(new JSValueObject
                {
                    { "freeSpace", status.free },
                    { "totalSpace", status.total },
                });
            }
            catch (Exception)
            {
                ReactError reactError = new ReactError();
                reactError.Message = "getFSInfo is not available";
                promise.Reject(reactError);
            }
        }

        [ReactMethod]
        public async void touch(string filepath, double mtime, double ctime, ReactPromise<JSValue> promise)
        {
            try
            {
                await Task.Run(() =>
                {
                    var fileInfo = new FileInfo(filepath);
                    if (!fileInfo.Exists)
                    {
                        using (File.Create(filepath)) { }
                    }

                    fileInfo.CreationTimeUtc = ConvertFromUnixTimestamp(ctime);
                    fileInfo.LastWriteTimeUtc = ConvertFromUnixTimestamp(mtime);

                    promise.Resolve(fileInfo.FullName);
                });
            }
            catch (Exception ex)
            {
                Reject(promise, filepath, ex);
            }
        }

        ~ReactNativeModule()
        {
            _tasks.CancelAllTasks();
            _httpClient.Dispose();
        }

        private async Task ProcessRequestAsync(ReactPromise<JSValue> promise, HttpRequestMessage request, string filepath, int jobId, int progressIncrement, CancellationToken token)
        {
            try
            {
                using (var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, token))
                {
                    var headersMap = new JSValueObject();
                    foreach (var header in response.Headers)
                    {
                        headersMap.Add(header.Key, string.Join(",", header.Value));
                    }

                    var contentLength = response.Content.Headers.ContentLength;
                    SendEvent($"DownloadBegin-{jobId}", new JSValueObject
                    {
                        { "jobId", jobId },
                        { "statusCode", (int)response.StatusCode },
                        { "contentLength", (long)contentLength },
                        { "headers", headersMap },
                    });

                    // TODO: open file on background thread?
                    long totalRead = 0;
                    using (var fileStream = File.OpenWrite(filepath))
                    using (var stream = await response.Content.ReadAsStreamAsync())
                    {
                        var contentLengthForProgress = contentLength ?? -1;
                        var nextProgressIncrement = progressIncrement;
                        var buffer = new byte[8 * 1024];
                        var read = 0;
                        while ((read = await stream.ReadAsync(buffer, 0, buffer.Length)) > 0)
                        {
                            token.ThrowIfCancellationRequested();

                            await fileStream.WriteAsync(buffer, 0, read);
                            if (contentLengthForProgress >= 0)
                            {
                                totalRead += read;
                                if (totalRead * 100 / contentLengthForProgress >= nextProgressIncrement ||
                                    totalRead == contentLengthForProgress)
                                {
                                    SendEvent("DownloadProgress-" + jobId, new JSValueObject
                                    {
                                        { "jobId", jobId },
                                        { "contentLength", (long)contentLength },
                                        { "bytesWritten", totalRead },
                                    });

                                    nextProgressIncrement += progressIncrement;
                                }
                            }
                        }
                    }

                    promise.Resolve(new JSValueObject
                    {
                        { "jobId", jobId },
                        { "statusCode", (int)response.StatusCode },
                        { "bytesWritten", totalRead },
                    });
                }
            }
            finally
            {
                request.Dispose();
            }
        }

        private void Reject(ReactPromise<JSValue> promise, String filepath, Exception ex)
        {
            if (ex is FileNotFoundException)
            {
                RejectFileNotFound(promise, filepath);
                return;
            }
            ReactError reactError = new ReactError();
            reactError.Exception = ex;
            promise.Reject(reactError);
        }

        private void RejectFileNotFound(ReactPromise<JSValue> promise, String filepath)
        {
            ReactError reactError = new ReactError();
            reactError.Code = "ENOENT";
            reactError.Message = "ENOENT: no such file or directory, open '" + filepath + "'";
            promise.Reject(reactError);
        }

        private void SendEvent(string eventName, JSValueObject eventData)
        {
            _reactContext.EmitJSEvent("RCTDeviceEventEmitter", eventName, eventData);
            // Emitter.emit(eventName, eventData);
        }

        public static double ConvertToUnixTimestamp(DateTime date)
        {
            var origin = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var diff = date.ToUniversalTime() - origin;
            return Math.Floor(diff.TotalSeconds);
        }

        public static DateTime ConvertFromUnixTimestamp(double timestamp)
        {
            var origin = new DateTime(1970, 1, 1, 0, 0, 0, 0, DateTimeKind.Utc);
            var diff = TimeSpan.FromSeconds(timestamp);
            var dateTimeUtc = origin + diff;
            return dateTimeUtc.ToLocalTime();
        }
    }

}
