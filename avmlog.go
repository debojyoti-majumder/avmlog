package main

import (
	"bufio"
	"compress/gzip"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Time layouts must use the reference time `Mon Jan 2 15:04:05 MST 2006` to
// convey the pattern with which to format/parse a given time/string
const TimeLayout string = "[2006-01-02 15:04:05 MST]"

// VERSION Simple version iformation about the module
const VERSION = "v4.0.1 - Enchantress"

// BufferSzie Maximum token size
const BufferSzie = bufio.MaxScanTokenSize

const REPORT_HEADERS = "RequestID, Method, URL, Computer, User, Request Result, Request Start, Request End, Request Time (ms), Db Time (ms), View Time (ms), Mount Time (ms), % Request Mounting, Mount Result, Errors, ESX-A, VC-A"

var jobRegexp *regexp.Regexp = regexp.MustCompile("^P[0-9]+(DJ|PW)[0-9]*")
var timestampRegexp *regexp.Regexp = regexp.MustCompile("^(\\[[0-9-]+ [0-9:]+ UTC\\])")
var request_regexp *regexp.Regexp = regexp.MustCompile("\\][[:space:]]+(P[0-9]+[A-Za-z]+[0-9]*) ")
var sql_regexp *regexp.Regexp = regexp.MustCompile("( SQL: | SQL \\()|(EXEC sp_executesql N)|( CACHE \\()")
var ntlm_regexp *regexp.Regexp = regexp.MustCompile(" (\\(NTLM\\)|NTLM:) ")
var debug_regexp *regexp.Regexp = regexp.MustCompile(" DEBUG ")
var error_regexp *regexp.Regexp = regexp.MustCompile("( ERROR | Exception | undefined | NilClass )")

var complete_regexp *regexp.Regexp = regexp.MustCompile(" Completed ([0-9]+) [A-Za-z ]+ in ([0-9.]+)ms \\(Views: ([0-9.]+)ms \\| ActiveRecord: ([0-9.]+)ms\\)")
var reconfig_regexp *regexp.Regexp = regexp.MustCompile(" RvSphere: Waking up in ReconfigVm#([a-z_]+) ")
var result_regexp *regexp.Regexp = regexp.MustCompile(" with result \\\"([a-z]+)\\\"")
var route_regexp *regexp.Regexp = regexp.MustCompile(" INFO Started ([A-Z]+) \\\"\\/([-a-zA-Z0-9_/]+)\\?")
var messageRegexp *regexp.Regexp = regexp.MustCompile(" P[0-9]+.*?[A-Z]+ (.*)")
var strip_regexp *regexp.Regexp = regexp.MustCompile("(_|-)?[0-9]+([_a-zA-Z0-9%!-]+)?")
var computer_regexp *regexp.Regexp = regexp.MustCompile("workstation=(.*?)&")
var user_regexp *regexp.Regexp = regexp.MustCompile("username=(.*?)&")

var vc_adapter_regexp *regexp.Regexp = regexp.MustCompile("Acquired 'vcenter' adapter ([0-9]+) of ([0-9]+) for '.*?' in ([0-9.]+)")
var esx_adapter_regexp *regexp.Regexp = regexp.MustCompile("Acquired 'esx' adapter ([0-9]+) of ([0-9]+) for '.*?' in ([0-9.]+)")

type mountReport struct {
	queue        bool
	mount_beg    string
	mount_end    string
	mount_result string
	ms_mount     float64
}

type request_report struct {
	step          int
	time_beg      string
	time_end      string
	mounts        []*mountReport
	method        string
	route         string
	computer      string
	user          string
	code          string
	ms_request    float64
	ms_garbage    float64
	msDb          float64
	ms_view       float64
	percent_mount int
	errors        int64
	vcAdapters    int64
	esx_adapters  int64
}

func main() {
	hideJobsFlag := flag.Bool("hide_jobs", false, "Hide background jobs")
	hide_sql_flag := flag.Bool("hide_sql", false, "Hide SQL statements")
	hide_ntlm_flag := flag.Bool("hide_ntlm", false, "Hide NTLM lines")
	hide_debug_flag := flag.Bool("hide_debug", false, "Hide DEBUG lines")
	only_msg_flag := flag.Bool("only_msg", false, "Output only the message portion")
	report_flag := flag.Bool("report", false, "Collect request report")
	fullFlag := flag.Bool("full", false, "Show the full request/job for each found line")
	neat_flag := flag.Bool("neat", false, "Hide clutter - equivalent to -hide_jobs -hide_sql -hide_ntlm")
	detect_errors := flag.Bool("detect_errors", false, "Detect lines containing known error messages")
	afterStr := flag.String("after", "", "Show logs after this time (YYYY-MM-DD HH:II::SS")
	find_str := flag.String("find", "", "Find lines matching this regexp")
	hide_str := flag.String("hide", "", "Hide lines matching this regexp")

	flag.Parse()
	args := flag.Args()

	timeAfter, err := time.Parse(TimeLayout, fmt.Sprintf("[%s UTC]", *afterStr))
	parse_time := false
	after_count := 0

	if err != nil {
		if len(*afterStr) > 0 {
			msg(fmt.Sprintf("Invalid time format \"%s\" - Must be YYYY-MM-DD HH::II::SS", *afterStr))
			usage()
			os.Exit(2)
		}
	} else {
		parse_time = true
	}

	if len(args) < 1 {
		usage()
		os.Exit(2)
	}

	if *neat_flag {
		*hideJobsFlag = true
		*hide_sql_flag = true
		*hide_ntlm_flag = true
	}

	msg(fmt.Sprintf("Show full requests/jobs: %t", *fullFlag))
	msg(fmt.Sprintf("Show background job lines: %t", !*hideJobsFlag))
	msg(fmt.Sprintf("Show SQL lines: %t", !*hide_sql_flag))
	msg(fmt.Sprintf("Show NTLM lines: %t", !*hide_ntlm_flag))
	msg(fmt.Sprintf("Show DEBUG lines: %t", !*hide_debug_flag))
	msg(fmt.Sprintf("Show lines after: %s", *afterStr))

	filename := args[0]
	msg(fmt.Sprintf("Opening file: %s", filename))

	file := openFile(filename)
	defer file.Close()

	is_gzip := isGzip(filename)
	file_size := float64(fileSize(file))
	show_percent := !is_gzip
	var readSize int64

	var reader io.Reader = file
	var unique_map map[string]bool
	var reports = map[string]*request_report{}

	if *detect_errors {
		*find_str = "( ERROR | Exception | undefined | Failed | NilClass | Unable | failed )"
	}

	find_regexp, err := regexp.Compile(*find_str)
	has_find := len(*find_str) > 0 && err == nil

	hide_regexp, err := regexp.Compile(*hide_str)
	has_hide := len(*hide_str) > 0 && err == nil

	if *report_flag || (*fullFlag && has_find) {
		if is_gzip {
			// for some reason if you create a reader but don't use it,
			// an error is given when the output reader is created below
			parse_gz_reader := getGzipReader(file)
			defer parse_gz_reader.Close()

			reader = parse_gz_reader
		}

		lineCount := 0
		line_after := !parse_time // if not parsing time, then all lines are valid
		requestIDs := make([]string, 0)
		adapter_cnt := int64(0)
		partialLine := false
		long_lines := 0

		reader := bufio.NewReaderSize(reader, BufferSzie)

		for {
			bytes, isPrefix, err := reader.ReadLine()

			line := string(bytes[:])

			if err == io.EOF {
				break
			}

			if err != nil {
				log.Fatal(err)
			}

			if isPrefix {
				if partialLine {
					continue
				} else {
					partialLine = true
					long_lines++
				}
			} else {
				partialLine = false
			}

			if find_regexp.MatchString(line) {

				if !line_after {
					if timestamp := extractTimestamp(line); len(timestamp) > 1 {
						if isAfterTime(timestamp, &timeAfter) {
							line_after = true
							after_count = lineCount
						}
					}
				}

				if line_after {
					if requestID := extractRequestId(line); len(requestID) > 1 {
						if *report_flag {
							if !isJob(requestID) {
								if timestamp := extractTimestamp(line); len(timestamp) > 1 {
									if report, ok := reports[requestID]; ok {
										if error_regexp.MatchString(line) {
											report.errors++
										} else if vc_adapter_match := vc_adapter_regexp.FindStringSubmatch(line); len(vc_adapter_match) > 1 {
											adapter_cnt, _ = strconv.ParseInt(vc_adapter_match[1], 10, 64)
											if adapter_cnt > report.vcAdapters {
												report.vcAdapters = adapter_cnt
											}
										} else if esx_adapter_match := esx_adapter_regexp.FindStringSubmatch(line); len(esx_adapter_match) > 1 {
											adapter_cnt, _ = strconv.ParseInt(esx_adapter_match[1], 10, 64)
											if adapter_cnt > report.esx_adapters {
												report.esx_adapters = adapter_cnt
											}
										} else if reconfig_match := reconfig_regexp.FindStringSubmatch(line); len(reconfig_match) > 1 {
											if reconfig_match[1] == "execute_task" {
												report.step++
												report.mounts = append(report.mounts, &mountReport{mount_beg: timestamp, queue: true})
											} else if reconfig_match[1] == "process_task" {
												if report.step >= 0 {
													if mount := report.mounts[report.step]; mount != nil {
														if mount.queue {
															mount.mount_end = timestamp
															if result_match := result_regexp.FindStringSubmatch(line); len(result_match) > 1 {
																mount.mount_result = result_match[1]
															}
															mount_beg_time, _ := time.Parse(TimeLayout, mount.mount_beg)
															mount_end_time, _ := time.Parse(TimeLayout, mount.mount_end)
															mount.ms_mount = mount_end_time.Sub(mount_beg_time).Seconds() * 1000
														} else {
															msg("We got a process task with no execute task")
														}
													}
												}
											}
										} else if complete_match := complete_regexp.FindStringSubmatch(line); len(complete_match) > 1 {
											report.time_end = timestamp
											report.code = complete_match[1]

											report.ms_request, _ = strconv.ParseFloat(complete_match[2], 64)
											report.ms_view, _ = strconv.ParseFloat(complete_match[3], 64)
											report.msDb, _ = strconv.ParseFloat(complete_match[4], 64)
										}
									} else {
										report := &request_report{step: -1, time_beg: timestamp}

										if route_match := route_regexp.FindStringSubmatch(line); len(route_match) > 1 {
											report.method = route_match[1]
											report.route = route_match[2]
										}

										if user_match := user_regexp.FindStringSubmatch(line); len(user_match) > 1 {
											report.user = user_match[1]
										}

										if computer_match := computer_regexp.FindStringSubmatch(line); len(computer_match) > 1 {
											report.computer = computer_match[1]
										}

										reports[requestID] = report
									}
								}
							}
						} else if !*hideJobsFlag || !isJob(requestID) {
							requestIDs = append(requestIDs, requestID)
						}
					}
				}
			}

			readSize += int64(len(line))

			if lineCount++; lineCount%20000 == 0 {
				if show_percent {
					showPercent(lineCount, float64(readSize)/file_size, line_after, len(requestIDs))
				} else {
					showBytes(lineCount, float64(readSize), line_after, len(requestIDs))
				}
			}
		}

		file_size = float64(readSize) // set the filesize to the total known size
		msg("")                       // empty line

		if long_lines > 0 {
			msg(fmt.Sprintf("Warning: truncated %d long lines that exceeded %d bytes", long_lines, BufferSzie))
		}

		if len(reports) > 0 {
			fmt.Println(REPORT_HEADERS)

			for k, v := range reports {
				if len(v.method) > 0 && len(v.time_end) > 0 {
					var ms_mount float64

					for _, mount := range v.mounts {
						ms_mount += mount.ms_mount
					}

					fmt.Println(fmt.Sprintf(
						"%s, %s, /%s, %s, %s, %s, %s, %s, %.2f, %.2f, %.2f, %.2f, %.2f%%, %d, %d, %d, %d",
						k,
						v.method,
						v.route,
						v.computer,
						v.user,
						v.code,
						v.time_beg,
						v.time_end,
						v.ms_request,
						v.msDb,
						v.ms_view,
						ms_mount,
						(ms_mount/v.ms_request)*100,
						len(v.mounts),
						v.errors,
						v.vcAdapters,
						v.esx_adapters))
				}
			}
			return
		}

		msg(fmt.Sprintf("Found %d lines matching \"%s\"", len(requestIDs), *find_str))
		unique_map = generateRequestIDMap(&requestIDs)

		if len(unique_map) < 1 {
			msg(fmt.Sprintf("Found 0 request identifiers for \"%s\"", *find_str))
			os.Exit(2)
		}

		rewindFile(file)
	} else {
		msg("Not printing -full requests, skipping request collection phase")
	}

	if is_gzip {
		output_gz_reader := getGzipReader(file)
		defer output_gz_reader.Close()

		reader = output_gz_reader
	}

	show_percent = readSize > int64(0)
	readSize = 0

	lineCount := 0
	line_after := !parse_time // if not parsing time, then all lines are valid
	has_requests := len(unique_map) > 0
	in_request := false

	output_reader := bufio.NewReaderSize(reader, BufferSzie)

	for {
		bytes, _, err := output_reader.ReadLine()

		line := string(bytes[:])

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatal(err)
		}

		output := false

		if !line_after {
			readSize += int64(len(line))

			if lineCount++; lineCount%5000 == 0 {
				if show_percent {
					fmt.Fprintf(os.Stderr, "Reading: %.2f%%\r", (float64(readSize)/file_size)*100)
				} else {
					fmt.Fprintf(os.Stderr, "Reading: %d lines, %0.3f GB\r", lineCount, float64(readSize)/1024/1024/1024)
				}
			}

			if after_count < lineCount {
				if timestamp := extractTimestamp(line); len(timestamp) > 1 {
					if isAfterTime(timestamp, &timeAfter) {
						msg("\n") // empty line
						line_after = true
					}
				}
			}
		}

		if line_after {
			requestID := extractRequestId(line)

			if has_requests {
				if len(requestID) > 0 {
					if unique_map[requestID] {
						if *hideJobsFlag && isJob(requestID) {
							output = false
						} else {
							in_request = true
							output = true
						}
					} else {
						in_request = false
					}

				} else if len(requestID) < 1 && in_request {
					output = true
				}
			} else if has_find {
				output = find_regexp.MatchString(line)
			} else {
				output = true
			}
		}

		if output {
			if *hide_sql_flag && sql_regexp.MatchString(line) {
				output = false
			} else if *hide_ntlm_flag && ntlm_regexp.MatchString(line) {
				output = false
			} else if *hide_debug_flag && debug_regexp.MatchString(line) {
				output = false
			} else if has_hide && hide_regexp.MatchString(line) {
				output = false
			}
		}

		if output {
			if *only_msg_flag {
				if messageMatch := messageRegexp.FindStringSubmatch(line); len(messageMatch) > 1 {
					fmt.Println(strip_regexp.ReplaceAllString(strings.TrimSpace(messageMatch[1]), "***"))
				}
			} else {
				fmt.Println(line)
			}
		}
	}
}

func usage() {
	msg("AppVolumes Manager Log Tool - " + VERSION)
	msg("This tool can be used to extract the logs for specific requests from an AppVolumes Manager log")
	msg("")
	msg("Example:avmlog -after=\"2015-10-19 09:00:00\" -find \"apvuser2599\" -full -neat ~/Documents/scale.log.gz")
	msg("")
	flag.PrintDefaults()
	msg("")
}

func isAfterTime(timestamp string, timeAfter *time.Time) bool {
	if lineTime, e := time.Parse(TimeLayout, timestamp); e != nil {
		msg(fmt.Sprintf("Got error %s", e))
		return false
	} else if lineTime.Before(*timeAfter) {
		return false
	}

	return true
}

func isJob(requestID string) bool {
	return jobRegexp.MatchString(requestID)
}

func extractTimestamp(line string) string {
	if timestampMatch := timestampRegexp.FindStringSubmatch(line); len(timestampMatch) > 1 {
		return timestampMatch[1]
	}

	return ""
}

func extractRequestId(line string) string {
	if request_match := request_regexp.FindStringSubmatch(line); len(request_match) > 1 {
		return request_match[1]
	} else {
		return ""
	}
}

func generateRequestIDMap(requestIds *[]string) map[string]bool {
	uniqueMap := make(map[string]bool, len(*requestIds))

	for _, x := range *requestIds {
		uniqueMap[x] = true
	}

	for k := range uniqueMap {
		msg(fmt.Sprintf("Request ID: %s", k))
	}

	return uniqueMap
}

func openFile(filename string) *os.File {
	file, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	return file
}

func fileSize(file *os.File) int64 {
	if fi, err := file.Stat(); err != nil {
		msg("Unable to determine file size")

		return 1
	} else {
		msg(fmt.Sprintf("The file is %d bytes long", fi.Size()))

		return fi.Size()
	}
}

func isGzip(filename string) bool {
	return strings.HasSuffix(filename, ".gz")
}

func getGzipReader(file *os.File) *gzip.Reader {
	gzReader, err := gzip.NewReader(file)
	if err != nil {
		log.Fatal(err)
	}

	return gzReader
}

func rewindFile(file *os.File) {
	file.Seek(0, 0) // go back to the top (rewind)
}

func msg(output string) {
	fmt.Fprintln(os.Stderr, output)
}

func showPercent(lineCount int, position float64, after bool, matches int) {
	fmt.Fprintf(
		os.Stderr,
		"Reading: %d lines, %.2f%% (after: %v, matches: %d)\r",
		lineCount,
		position*100,
		after,
		matches)
}

func showBytes(lineCount int, position float64, after bool, matches int) {
	fmt.Fprintf(
		os.Stderr,
		"Reading: %d lines, %0.3f GB (after: %v, matches: %d)\r",
		lineCount,
		position/1024/1024/1024,
		after,
		matches)
}

// TODO: How to combine and re-order two (or more) log files
// open file1
// open file2
// loop start
// if file1 timestamp is blank - read file1 line, store line and it's timestamp
// if file2 timestamp is blank - read file2 line, store line and it's timestamp
// if file1 < file2
// print file1
// clear file1 timestamp
// else
// print file2
// clear file2 timestamp
//
