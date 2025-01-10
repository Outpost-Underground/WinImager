using System;
using System.ComponentModel;
using System.IO;
using System.Management;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using System.Windows.Forms;

namespace WinImager
{
    public partial class MainForm : Form
    {
        public MainForm()
        {
            InitializeComponent();
            LoadPhysicalDrives();
        }

        // ADDED: Helper method to retrieve Model & SerialNumber from Win32_DiskDrive
        private (string model, string serial) GetDriveInfo(string physicalDrivePath)
        {
            string model = "Unknown Model";
            string serial = "Unknown Serial";

            // Example: physicalDrivePath might be "\\.\PHYSICALDRIVE0"
            // We'll match that to Win32_DiskDrive.DeviceID
            string wmiPath = physicalDrivePath.Replace("\\", "\\\\"); // escape backslashes for WQL
            string query = $"SELECT * FROM Win32_DiskDrive WHERE DeviceID = \"{wmiPath}\"";
            var searcher = new ManagementObjectSearcher(query);

            foreach (ManagementObject obj in searcher.Get())
            {
                model = obj["Model"]?.ToString() ?? "Unknown Model";
                serial = obj["SerialNumber"]?.ToString() ?? "Unknown Serial";
                break; // take the first match
            }

            return (model, serial);
        }

        public class ImagingResult
        {
            public StringBuilder LogBuilder { get; } = new StringBuilder();
            public long TotalBytesRead { get; set; }
            public long TotalBytes { get; set; }
            public long SuccessfulChunks { get; set; }
            public long ErrorChunks { get; set; }
            public string DrivePath { get; set; }
            public string OutputFile { get; set; }
            public bool Completed { get; set; }

            // Hash arrays
            public byte[] Md5Source { get; set; }
            public byte[] Md5Image { get; set; }
            public byte[] Sha1Source { get; set; }
            public byte[] Sha1Image { get; set; }
        }

        private void LoadPhysicalDrives()
        {
            comboBoxDrives.Items.Clear();
            try
            {
                var searcher = new ManagementObjectSearcher("SELECT * FROM Win32_DiskDrive");
                foreach (ManagementObject obj in searcher.Get())
                {
                    string deviceId = obj["DeviceID"]?.ToString();
                    string sizeStr = obj["Size"]?.ToString();

                    if (!string.IsNullOrEmpty(deviceId))
                    {
                        long size;
                        long.TryParse(sizeStr, out size);
                        string displayText = $"{deviceId} ({FormatBytes(size)})";
                        comboBoxDrives.Items.Add(displayText);
                    }
                }
                if (comboBoxDrives.Items.Count > 0)
                    comboBoxDrives.SelectedIndex = 0;
            }
            catch (Exception ex)
            {
                MessageBox.Show("Failed to list physical drives:\n" + ex.Message);
            }
        }

        private string FormatBytes(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            double kb = bytes / 1024.0;
            if (kb < 1024) return $"{kb:F2} KB";
            double mb = kb / 1024.0;
            if (mb < 1024) return $"{mb:F2} MB";
            double gb = mb / 1024.0;
            if (gb < 1024) return $"{gb:F2} GB";
            double tb = gb / 1024.0;
            return $"{tb:F2} TB";
        }

        private void buttonBrowse_Click(object sender, EventArgs e)
        {
            using (var sfd = new SaveFileDialog())
            {
                sfd.Title = "Select Destination Image File";
                sfd.Filter = "Image Files (*.img)|*.img|All Files (*.*)|*.*";
                if (sfd.ShowDialog() == DialogResult.OK)
                {
                    textBoxDestination.Text = sfd.FileName;
                }
            }
        }

        private void buttonCreateImage_Click(object sender, EventArgs e)
        {
            if (comboBoxDrives.SelectedItem == null)
            {
                MessageBox.Show("Please select a physical drive.");
                return;
            }
            if (string.IsNullOrWhiteSpace(textBoxDestination.Text))
            {
                MessageBox.Show("Please specify an output file.");
                return;
            }

            // e.g. "\\.\PHYSICALDRIVE0 (500 GB)"
            string selectedDrive = comboBoxDrives.SelectedItem.ToString();
            string drivePath = selectedDrive.Split(' ')[0];
            string outputFile = textBoxDestination.Text;

            // Disable UI
            buttonCreateImage.Enabled = false;
            buttonBrowse.Enabled = false;
            comboBoxDrives.Enabled = false;
            numericUpDownChunkMB.Enabled = false;
            checkBoxGentle.Enabled = false;
            checkBoxComputeHashes.Enabled = false;

            backgroundWorker1.RunWorkerAsync(new Tuple<string, string>(drivePath, outputFile));
        }

        private void backgroundWorker1_DoWork(object sender, DoWorkEventArgs e)
        {
            var args = (Tuple<string, string>)e.Argument;
            string drivePath = args.Item1;
            string outputFile = args.Item2;

            ImagingResult result = new ImagingResult
            {
                DrivePath = drivePath,
                OutputFile = outputFile
            };

            try
            {
                // ADDED: Get drive model & serial
                var (srcModel, srcSerial) = GetDriveInfo(drivePath);

                // ADDED: Imaging start time
                DateTime imagingStart = DateTime.Now;

                // 1) Get geometry from DeviceIoControl
                var geometryEx = DriveGeometryHelper.GetDriveGeometryEx(drivePath);
                long totalBytes = geometryEx.DiskSize;
                int bytesPerSector = geometryEx.Geometry.BytesPerSector;

                result.TotalBytes = totalBytes;

                // Build log
                result.LogBuilder.AppendLine("=== Begin Imaging Log ===");
                result.LogBuilder.AppendLine($"Drive Path  : {drivePath}");
                result.LogBuilder.AppendLine($"Model       : {srcModel}");   // ADDED
                result.LogBuilder.AppendLine($"Serial      : {srcSerial}");  // ADDED
                result.LogBuilder.AppendLine($"Imaging started: {imagingStart}"); // ADDED
                result.LogBuilder.AppendLine($"Total Bytes (geometry): {totalBytes}");
                result.LogBuilder.AppendLine($"Bytes Per Sector: {bytesPerSector}");

                // 2) Chunk size
                int userChunkMB = (int)numericUpDownChunkMB.Value;
                long chunkSize = userChunkMB * 1024L * 1024L;
                if (chunkSize < bytesPerSector) chunkSize = bytesPerSector;

                bool gentleMode = checkBoxGentle.Checked;
                bool doHashes = checkBoxComputeHashes.Checked;

                result.LogBuilder.AppendLine($"Chunk Size  : {userChunkMB} MB => {chunkSize} bytes");
                result.LogBuilder.AppendLine($"Gentle Mode : {gentleMode}");
                result.LogBuilder.AppendLine($"Compute MD5/SHA1: {doHashes}");

                // Prepare hashes
                MD5 md5Source = null, md5Image = null;
                SHA1 sha1Source = null, sha1Image = null;
                if (doHashes)
                {
                    md5Source = MD5.Create();
                    md5Image = MD5.Create();
                    sha1Source = SHA1.Create();
                    sha1Image = SHA1.Create();
                }

                // Open drive (raw) and output file
                using (var driveHandle = NativeMethods.CreateFile(
                    drivePath,
                    NativeMethods.GENERIC_READ,
                    NativeMethods.FILE_SHARE_READ | NativeMethods.FILE_SHARE_WRITE,
                    IntPtr.Zero,
                    NativeMethods.OPEN_EXISTING,
                    0,
                    IntPtr.Zero))
                {
                    if (driveHandle.IsInvalid)
                    {
                        throw new System.ComponentModel.Win32Exception(
                            System.Runtime.InteropServices.Marshal.GetLastWin32Error(),
                            "Unable to open drive in raw mode.");
                    }

                    // NOTE: "ReadWrite" so we can re-read the output file for hashing
                    using (FileStream driveStream = new FileStream(driveHandle, FileAccess.Read))
                    using (FileStream outStream = new FileStream(outputFile,
                                                  FileMode.Create,
                                                  FileAccess.ReadWrite,
                                                  FileShare.None))
                    {
                        byte[] buffer = new byte[chunkSize];
                        long totalBytesRead = 0;

                        // PHASE 1: IMAGING
                        while (true)
                        {
                            if (backgroundWorker1.CancellationPending)
                            {
                                e.Cancel = true;
                                result.LogBuilder.AppendLine("User cancelled operation.");
                                break;
                            }

                            long bytesRemaining = totalBytes - totalBytesRead;
                            if (bytesRemaining <= 0) break;

                            int toRead = (int)Math.Min(chunkSize, bytesRemaining);
                            int bytesRead = 0;
                            bool readSuccess = false;

                            try
                            {
                                bytesRead = driveStream.Read(buffer, 0, toRead);
                                readSuccess = true;
                            }
                            catch (IOException ioEx)
                            {
                                result.LogBuilder.AppendLine(
                                    $"[ERROR] Reading offset {totalBytesRead}: {ioEx.Message}");
                                // zero-fill
                                Array.Clear(buffer, 0, toRead);
                                bytesRead = toRead;
                            }

                            if (bytesRead < toRead)
                            {
                                // partial read (EOF or error)
                                result.LogBuilder.AppendLine(
                                    $"Partial read at offset {totalBytesRead}, bytesRead={bytesRead}/{toRead}");
                            }

                            outStream.Write(buffer, 0, bytesRead);
                            totalBytesRead += bytesRead;

                            if (readSuccess && bytesRead == toRead)
                                result.SuccessfulChunks++;
                            else
                                result.ErrorChunks++;

                            // update MD5/SHA1 for source
                            if (doHashes && bytesRead > 0)
                            {
                                md5Source?.TransformBlock(buffer, 0, bytesRead, null, 0);
                                sha1Source?.TransformBlock(buffer, 0, bytesRead, null, 0);
                            }

                            // Report imaging progress
                            double imagingPercent = (double)totalBytesRead / totalBytes * 100.0;
                            backgroundWorker1.ReportProgress((int)imagingPercent, "IMAGING");

                            if (gentleMode) Thread.Sleep(10);
                        }

                        if (doHashes)
                        {
                            md5Source?.TransformFinalBlock(new byte[0], 0, 0);
                            sha1Source?.TransformFinalBlock(new byte[0], 0, 0);
                        }

                        result.TotalBytesRead = totalBytesRead;

                        // ADDED: Imaging end time
                        DateTime imagingEnd = DateTime.Now;
                        result.LogBuilder.AppendLine($"Imaging ended: {imagingEnd}");
                        TimeSpan imagingDuration = imagingEnd - imagingStart;
                        result.LogBuilder.AppendLine($"Imaging duration: {imagingDuration}");

                        // PHASE 2: HASHING (if not canceled and doHashes is true)
                        if (!e.Cancel && doHashes)
                        {
                            // ADDED: Hashing start
                            DateTime hashingStart = DateTime.Now;
                            result.LogBuilder.AppendLine($"Hashing started: {hashingStart}");

                            outStream.Flush();
                            outStream.Seek(0, SeekOrigin.Begin);

                            long imageLength = outStream.Length;
                            long imageBytesRead = 0;
                            byte[] hashBuf = new byte[4 * 1024 * 1024]; // 4 MB read for hashing
                            int readCount;

                            while ((readCount = outStream.Read(hashBuf, 0, hashBuf.Length)) > 0)
                            {
                                md5Image?.TransformBlock(hashBuf, 0, readCount, null, 0);
                                sha1Image?.TransformBlock(hashBuf, 0, readCount, null, 0);

                                imageBytesRead += readCount;

                                // report hashing progress
                                double hashPercent = (double)imageBytesRead / imageLength * 100.0;
                                backgroundWorker1.ReportProgress((int)hashPercent, "HASHING");
                            }

                            md5Image?.TransformFinalBlock(new byte[0], 0, 0);
                            sha1Image?.TransformFinalBlock(new byte[0], 0, 0);

                            result.Md5Source = md5Source?.Hash;
                            result.Sha1Source = sha1Source?.Hash;
                            result.Md5Image = md5Image?.Hash;
                            result.Sha1Image = sha1Image?.Hash;

                            // ADDED: Hashing end
                            DateTime hashingEnd = DateTime.Now;
                            result.LogBuilder.AppendLine($"Hashing ended: {hashingEnd}");
                            TimeSpan hashingDuration = hashingEnd - hashingStart;
                            result.LogBuilder.AppendLine($"Hashing duration: {hashingDuration}");
                        }

                        result.Completed = true;
                        result.LogBuilder.AppendLine($"Total Bytes Read: {result.TotalBytesRead}");
                        result.LogBuilder.AppendLine(
                            $"Successful Chunks: {result.SuccessfulChunks}, " +
                            $"Error Chunks: {result.ErrorChunks}");

                        // If doHashes + not canceled
                        if (doHashes && !e.Cancel)
                        {
                            // Convert byte arrays to hex
                            string md5Src = result.Md5Source == null
                                ? "N/A"
                                : BitConverter.ToString(result.Md5Source).Replace("-", "");
                            string sha1Src = result.Sha1Source == null
                                ? "N/A"
                                : BitConverter.ToString(result.Sha1Source).Replace("-", "");
                            string md5Img = result.Md5Image == null
                                ? "N/A"
                                : BitConverter.ToString(result.Md5Image).Replace("-", "");
                            string sha1Img = result.Sha1Image == null
                                ? "N/A"
                                : BitConverter.ToString(result.Sha1Image).Replace("-", "");

                            result.LogBuilder.AppendLine();
                            result.LogBuilder.AppendLine("Source MD5 : " + md5Src);
                            result.LogBuilder.AppendLine("Source SHA1: " + sha1Src);
                            result.LogBuilder.AppendLine("Image  MD5 : " + md5Img);
                            result.LogBuilder.AppendLine("Image  SHA1: " + sha1Img);
                        }

                        result.LogBuilder.AppendLine("=== End of Imaging Log ===");
                        e.Result = result;
                    }
                }
            }
            catch (Exception ex)
            {
                e.Result = ex;
            }
        }

        private void backgroundWorker1_ProgressChanged(object sender, ProgressChangedEventArgs e)
        {
            string phase = e.UserState as string;
            int percent = e.ProgressPercentage;

            if (phase == "HASHING")
            {
                // second progress bar for hashing
                progressBarHash.Value = percent;
                labelHashProgress.Text = $"Hash Progress: {percent}%";
            }
            else
            {
                // IMAGING phase or default
                progressBar1.Value = percent;
                labelProgress.Text = $"Progress: {percent}%";
            }
        }

        private void backgroundWorker1_RunWorkerCompleted(object sender, RunWorkerCompletedEventArgs e)
        {
            // Re-enable UI
            buttonCreateImage.Enabled = true;
            buttonBrowse.Enabled = true;
            comboBoxDrives.Enabled = true;
            numericUpDownChunkMB.Enabled = true;
            checkBoxGentle.Enabled = true;
            checkBoxComputeHashes.Enabled = true;

            // reset hash progress
            progressBarHash.Value = 0;
            labelHashProgress.Text = "Hash Progress:";

            if (e.Cancelled)
            {
                labelProgress.Text = "Imaging cancelled.";
                return;
            }
            else if (e.Error != null)
            {
                labelProgress.Text = "Error during imaging.";
                MessageBox.Show($"Exception: {e.Error.Message}", "Error",
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            else if (e.Result is Exception ex)
            {
                labelProgress.Text = "Error during imaging.";
                MessageBox.Show($"Exception: {ex.Message}", "Error",
                                MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }

            var result = e.Result as ImagingResult;
            if (result != null)
            {
                labelProgress.Text = result.Completed ? "Imaging complete!" : "Incomplete";

                // Write log to .txt
                string logFilePath = Path.ChangeExtension(result.OutputFile, ".txt");
                File.WriteAllText(logFilePath, result.LogBuilder.ToString(), Encoding.UTF8);

                // Show summary
                StringBuilder sb = new StringBuilder();
                sb.AppendLine("Imaging finished.");
                sb.AppendLine($"Bytes read: {result.TotalBytesRead}");
                sb.AppendLine($"Chunks OK: {result.SuccessfulChunks}, Chunks error: {result.ErrorChunks}");
                sb.AppendLine($"Log saved to: {logFilePath}");

                if (result.Md5Source != null && result.Md5Image != null)
                {
                    sb.AppendLine();
                    sb.AppendLine("Source MD5 : " +
                        BitConverter.ToString(result.Md5Source).Replace("-", ""));
                    sb.AppendLine("Image  MD5 : " +
                        BitConverter.ToString(result.Md5Image).Replace("-", ""));
                }
                if (result.Sha1Source != null && result.Sha1Image != null)
                {
                    sb.AppendLine();
                    sb.AppendLine("Source SHA1: " +
                        BitConverter.ToString(result.Sha1Source).Replace("-", ""));
                    sb.AppendLine("Image  SHA1: " +
                        BitConverter.ToString(result.Sha1Image).Replace("-", ""));
                }

                MessageBox.Show(sb.ToString(), "Imaging Report",
                                MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            else
            {
                labelProgress.Text = "Imaging complete (no result?).";
            }
        }

        private void numericUpDownChunkMB_ValueChanged(object sender, EventArgs e)
        {
            // Optionally handle user changes to chunk size in real time
        }

        private void checkBoxComputeHashes_CheckedChanged(object sender, EventArgs e)
        {
            // Optionally handle if user toggles hashing on/off
        }
    }
}



