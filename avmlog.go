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

// TimeLayout must use the reference time `Mon Jan 2 15:04:05 MST 2006` to
// convey the pattern with which to format/parse a given time/string
const TimeLayout string = "[2006-01-02 15:04:05 MST]"

// VERSION Simple version iformation about the module
const VERSION = "v4.0.1 - Enchantress"

// BufferSzie Maximum token size
const BufferSzie = bufio.MaxScanTokenSize

// ReportHeaders is for file header to be parsed
const ReportHeaders = "RequestID, Method, URL, Computer, User, Request Result, Request Start, Request End, Request Time (ms), Db Time (ms), View Time (ms), Mount Time (ms), % Request Mounting, Mount Result, Errors, ESX-A, VC-A"

var jobRegexp *regexp.Regexp = regexp.MustCompile("^P[0-9]+(DJ|PW)[0-9]*")
var timestampRegexp *regexp.Regexp = regexp.MustCompile("^(\\[[0-9-]+ [0-9:]+ UTC\\])")
var requestRegexp *regexp.Regexp = regexp.MustCompile("\\][[:space:]]+(P[0-9]+[A-Za-z]+[0-9]*) ")
var sqlRegexp *regexp.Regexp = regexp.MustCompile("( SQL: | SQL \\()|(EXEC sp_executesql N)|( CACHE \\()")
var ntlmRegexp *regexp.Regexp = regexp.MustCompile(" (\\(NTLM\\)|NTLM:) ")
var debugRegexp *regexp.Regexp = regexp.MustCompile(" DEBUG ")
var errorRegexp *regexp.Regexp = regexp.MustCompile("( ERROR | Exception | undefined | NilClass )")

var completeRegexp *regexp.Regexp = regexp.MustCompile(" Completed ([0-9]+) [A-Za-z ]+ in ([0-9.]+)ms \\(Views: ([0-9.]+)ms \\| ActiveRecord: ([0-9.]+)ms\\)")
var reconfigRegexp *regexp.Regexp = regexp.MustCompile(" RvSphere: Waking up in ReconfigVm#([a-z_]+) ")
var resultRegexp *regexp.Regexp = regexp.MustCompile(" with result \\\"([a-z]+)\\\"")
var routeRegexp *regexp.Regexp = regexp.MustCompile(" INFO Started ([A-Z]+) \\\"\\/([-a-zA-Z0-9_/]+)\\?")
var messageRegexp *regexp.Regexp = regexp.MustCompile(" P[0-9]+.*?[A-Z]+ (.*)")
var stripRegexp *regexp.Regexp = regexp.MustCompile("(_|-)?[0-9]+([_a-zA-Z0-9%!-]+)?")
var computerRegexp *regexp.Regexp = regexp.MustCompile("workstation=(.*?)&")
var userRegexp *regexp.Regexp = regexp.MustCompile("username=(.*?)&")

var vcAdapterRegexp *regexp.Regexp = regexp.MustCompile("Acquired 'vcenter' adapter ([0-9]+) of ([0-9]+) for '.*?' in ([0-9.]+)")
var esxAdapterRegexp *regexp.Regexp = regexp.MustCompile("Acquired 'esx' adapter ([0-9]+) of ([0-9]+) for '.*?' in ([0-9.]+)")

type mountReport struct {
	queue       bool
	mountBeg    string
	mountEnd    string
	mountResult string
	msMount     float64
}

// RequestReport Report for incoming request
type RequestReport struct {
	step         int
	timeBeg      string
	timeEnd      string
	mounts       []*mountReport
	method       string
	route        string
	computer     string
	user         string
	code         string
	msRequest    float64
	msGarbage    float64
	msDb         float64
	msView       float64
	percentMount int
	errors       int64
	vcAdapters   int64
	esxAdapters  int64
}

func main() {
	hideJobsFlag := flag.Bool("hide_jobs", false, "Hide background jobs")
	hideSQLFlag := flag.Bool("hide_sql", false, "Hide SQL statements")
	hideNtlmFlag := flag.Bool("hide_ntlm", false, "Hide NTLM lines")
	hideDebugFlag := flag.Bool("hide_debug", false, "Hide DEBUG lines")
	onlyMsgFlag := flag.Bool("only_msg", false, "Output only the message portion")
	reportFlag := flag.Bool("report", false, "Collect request report")
	fullFlag := flag.Bool("full", false, "Show the full request/job for each found line")
	neatFlag := flag.Bool("neat", false, "Hide clutter - equivalent to -hide_jobs -hide_sql -hide_ntlm")
	detectErrors := flag.Bool("detectErrors", false, "Detect lines containing known error messages")
	afterStr := flag.String("after", "", "Show logs after this time (YYYY-MM-DD HH:II::SS")
	findStr := flag.String("find", "", "Find lines matching this regexp")
	hideStr := flag.String("hide", "", "Hide lines matching this regexp")

	flag.Parse()
	args := flag.Args()

	timeAfter, err := time.Parse(TimeLayout, fmt.Sprintf("[%s UTC]", *afterStr))
	parseTime := false
	afterCount := 0

	if err != nil {
		if len(*afterStr) > 0 {
			msg(fmt.Sprintf("Invalid time format \"%s\" - Must be YYYY-MM-DD HH::II::SS", *afterStr))
			usage()
			os.Exit(2)
		}
	} else {
		parseTime = true
	}

	if len(args) < 1 {
		usage()
		os.Exit(2)
	}

	if *neatFlag {
		*hideJobsFlag = true
		*hideSQLFlag = true
		*hideNtlmFlag = true
	}

	msg(fmt.Sprintf("Show full requests/jobs: %t", *fullFlag))
	msg(fmt.Sprintf("Show background job lines: %t", !*hideJobsFlag))
	msg(fmt.Sprintf("Show SQL lines: %t", !*hideSQLFlag))
	msg(fmt.Sprintf("Show NTLM lines: %t", !*hideNtlmFlag))
	msg(fmt.Sprintf("Show DEBUG lines: %t", !*hideDebugFlag))
	msg(fmt.Sprintf("Show lines after: %s", *afterStr))

	filename := args[0]
	msg(fmt.Sprintf("Opening file: %s", filename))

	file := openFile(filename)
	defer file.Close()

	isGzip := isGzip(filename)
	fileSize := float64(fileSize(file))
	showPercent := !isGzip
	var readSize int64

	var reader io.Reader = file
	var uniqueMap map[string]bool
	var reports = map[string]*RequestReport{}

	if *detectErrors {
		*findStr = "( ERROR | Exception | undefined | Failed | NilClass | Unable | failed )"
	}

	findRegexp, err := regexp.Compile(*findStr)
	hasFind := len(*findStr) > 0 && err == nil

	hideRegexp, err := regexp.Compile(*hideStr)
	hasHide := len(*hideStr) > 0 && err == nil

	if *reportFlag || (*fullFlag && hasFind) {
		if isGzip {
			// for some reason if you create a reader but don't use it,
			// an error is given when the output reader is created below
			parseGzReader := getGzipReader(file)
			defer parseGzReader.Close()

			reader = parseGzReader
		}

		lineCount := 0
		lineAfter := !parseTime // if not parsing time, then all lines are valid
		requestIDs := make([]string, 0)
		adapterCnt := int64(0)
		partialLine := false
		longLines := 0

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
					longLines++
				}
			} else {
				partialLine = false
			}

			if findRegexp.MatchString(line) {

				if !lineAfter {
					if timestamp := extractTimestamp(line); len(timestamp) > 1 {
						if isAfterTime(timestamp, &timeAfter) {
							lineAfter = true
							afterCount = lineCount
						}
					}
				}

				if lineAfter {
					if requestID := extractRequestID(line); len(requestID) > 1 {
						if *reportFlag {
							if !isJob(requestID) {
								if timestamp := extractTimestamp(line); len(timestamp) > 1 {
									if report, ok := reports[requestID]; ok {
										if errorRegexp.MatchString(line) {
											report.errors++
										} else if vcAdapterMatch := vcAdapterRegexp.FindStringSubmatch(line); len(vcAdapterMatch) > 1 {
											adapterCnt, _ = strconv.ParseInt(vcAdapterMatch[1], 10, 64)
											if adapterCnt > report.vcAdapters {
												report.vcAdapters = adapterCnt
											}
										} else if esxAdapterMatch := esxAdapterRegexp.FindStringSubmatch(line); len(esxAdapterMatch) > 1 {
											adapterCnt, _ = strconv.ParseInt(esxAdapterMatch[1], 10, 64)
											if adapterCnt > report.esxAdapters {
												report.esxAdapters = adapterCnt
											}
										} else if reconfigMatch := reconfigRegexp.FindStringSubmatch(line); len(reconfigMatch) > 1 {
											if reconfigMatch[1] == "execute_task" {
												report.step++
												report.mounts = append(report.mounts, &mountReport{mountBeg: timestamp, queue: true})
											} else if reconfigMatch[1] == "process_task" {
												if report.step >= 0 {
													if mount := report.mounts[report.step]; mount != nil {
														if mount.queue {
															mount.mountEnd = timestamp
															if resultMatch := resultRegexp.FindStringSubmatch(line); len(resultMatch) > 1 {
																mount.mountResult = resultMatch[1]
															}
															mountBegTime, _ := time.Parse(TimeLayout, mount.mountBeg)
															mountEndTime, _ := time.Parse(TimeLayout, mount.mountEnd)
															mount.msMount = mountEndTime.Sub(mountBegTime).Seconds() * 1000
														} else {
															msg("We got a process task with no execute task")
														}
													}
												}
											}
										} else if completeMatch := completeRegexp.FindStringSubmatch(line); len(completeMatch) > 1 {
											report.timeEnd = timestamp
											report.code = completeMatch[1]

											report.msRequest, _ = strconv.ParseFloat(completeMatch[2], 64)
											report.msView, _ = strconv.ParseFloat(completeMatch[3], 64)
											report.msDb, _ = strconv.ParseFloat(completeMatch[4], 64)
										}
									} else {
										report := &RequestReport{step: -1, timeBeg: timestamp}

										if routeMatch := routeRegexp.FindStringSubmatch(line); len(routeMatch) > 1 {
											report.method = routeMatch[1]
											report.route = routeMatch[2]
										}

										if userMatch := userRegexp.FindStringSubmatch(line); len(userMatch) > 1 {
											report.user = userMatch[1]
										}

										if computerMatch := computerRegexp.FindStringSubmatch(line); len(computerMatch) > 1 {
											report.computer = computerMatch[1]
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
				if showPercent {
					showPercentOutput(lineCount, float64(readSize)/fileSize, lineAfter, len(requestIDs))
				} else {
					showBytes(lineCount, float64(readSize), lineAfter, len(requestIDs))
				}
			}
		}

		fileSize = float64(readSize) // set the filesize to the total known size
		msg("")                      // empty line

		if longLines > 0 {
			msg(fmt.Sprintf("Warning: truncated %d long lines that exceeded %d bytes", longLines, BufferSzie))
		}

		if len(reports) > 0 {
			fmt.Println(ReportHeaders)

			for k, v := range reports {
				if len(v.method) > 0 && len(v.timeEnd) > 0 {
					var msMount float64

					for _, mount := range v.mounts {
						msMount += mount.msMount
					}

					fmt.Println(fmt.Sprintf(
						"%s, %s, /%s, %s, %s, %s, %s, %s, %.2f, %.2f, %.2f, %.2f, %.2f%%, %d, %d, %d, %d",
						k,
						v.method,
						v.route,
						v.computer,
						v.user,
						v.code,
						v.timeBeg,
						v.timeEnd,
						v.msRequest,
						v.msDb,
						v.msView,
						msMount,
						(msMount/v.msRequest)*100,
						len(v.mounts),
						v.errors,
						v.vcAdapters,
						v.esxAdapters))
				}
			}
			return
		}

		msg(fmt.Sprintf("Found %d lines matching \"%s\"", len(requestIDs), *findStr))
		uniqueMap = generateRequestIDMap(&requestIDs)

		if len(uniqueMap) < 1 {
			msg(fmt.Sprintf("Found 0 request identifiers for \"%s\"", *findStr))
			os.Exit(2)
		}

		rewindFile(file)
	} else {
		msg("Not printing -full requests, skipping request collection phase")
	}

	if isGzip {
		outputGzReader := getGzipReader(file)
		defer outputGzReader.Close()

		reader = outputGzReader
	}

	showPercent = readSize > int64(0)
	readSize = 0

	lineCount := 0
	lineAfter := !parseTime // if not parsing time, then all lines are valid
	hasRequests := len(uniqueMap) > 0
	inRequest := false

	outputReader := bufio.NewReaderSize(reader, BufferSzie)

	for {
		bytes, _, err := outputReader.ReadLine()

		line := string(bytes[:])

		if err == io.EOF {
			break
		}

		if err != nil {
			log.Fatal(err)
		}

		output := false

		if !lineAfter {
			readSize += int64(len(line))

			if lineCount++; lineCount%5000 == 0 {
				if showPercent {
					fmt.Fprintf(os.Stderr, "Reading: %.2f%%\r", (float64(readSize)/fileSize)*100)
				} else {
					fmt.Fprintf(os.Stderr, "Reading: %d lines, %0.3f GB\r", lineCount, float64(readSize)/1024/1024/1024)
				}
			}

			if afterCount < lineCount {
				if timestamp := extractTimestamp(line); len(timestamp) > 1 {
					if isAfterTime(timestamp, &timeAfter) {
						msg("\n") // empty line
						lineAfter = true
					}
				}
			}
		}

		if lineAfter {
			requestID := extractRequestID(line)

			if hasRequests {
				if len(requestID) > 0 {
					if uniqueMap[requestID] {
						if *hideJobsFlag && isJob(requestID) {
							output = false
						} else {
							inRequest = true
							output = true
						}
					} else {
						inRequest = false
					}

				} else if len(requestID) < 1 && inRequest {
					output = true
				}
			} else if hasFind {
				output = findRegexp.MatchString(line)
			} else {
				output = true
			}
		}

		if output {
			if *hideSQLFlag && sqlRegexp.MatchString(line) {
				output = false
			} else if *hideNtlmFlag && ntlmRegexp.MatchString(line) {
				output = false
			} else if *hideDebugFlag && debugRegexp.MatchString(line) {
				output = false
			} else if hasHide && hideRegexp.MatchString(line) {
				output = false
			}
		}

		if output {
			if *onlyMsgFlag {
				if messageMatch := messageRegexp.FindStringSubmatch(line); len(messageMatch) > 1 {
					fmt.Println(stripRegexp.ReplaceAllString(strings.TrimSpace(messageMatch[1]), "***"))
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

func extractRequestID(line string) string {
	if requestMatch := requestRegexp.FindStringSubmatch(line); len(requestMatch) > 1 {
		return requestMatch[1]
	}

	return ""
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
	fi, err := file.Stat()

	if err != nil {
		msg("Unable to determine file size")

		return 1
	}

	msg(fmt.Sprintf("The file is %d bytes long", fi.Size()))
	return fi.Size()
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

func showPercentOutput(lineCount int, position float64, after bool, matches int) {
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
