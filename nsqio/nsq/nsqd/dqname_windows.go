// +build windows

package nsqd

// On Windows, file names cannot contain colons.
//获取缓冲二级存储队列名字
func getBackendName(topicName, channelName string) string {
	// backend names, for uniqueness, automatically include the topic... <topic>;<channel>
	backendName := topicName + ";" + channelName
	return backendName
}
