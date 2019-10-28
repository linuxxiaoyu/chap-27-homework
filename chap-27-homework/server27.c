#include "lib/common.h"
#include "lib/acceptor.h"


int onConnectionCompleted(struct tcp_connection *tcpConnection) {
	printf("connection completed\n");
	return 0;
}

char *run_cmd(char *cmd) {
	char *data = malloc(16384);
	bzero(data, sizeof(data));
	FILE *fdp;
	const int max_buffer = 256;
	char buffer[max_buffer];
	fdp = popen(cmd, "r");
	char *data_index = data;
	if (fdp) {
		while (!feof(fdp)) {
			if (fgets(buffer, max_buffer, fdp) != NULL) {
				int len = strlen(buffer);
				memcpy(data_index, buffer, len);
				data_index += len;
			}
		}
		pclose(fdp);
	}
	return data;
}

int onMessage(struct buffer *input, struct tcp_connection *tcpConnection) {
	printf("get message from tcp connection %s\n", tcpConnection->name);
	printf("%s", input->data);

	char buf[256] = {0};
	struct buffer *output = buffer_new();
	int size = buffer_readable_size(input);
	for (int i = 0; i < size; i++) {
		buf[i] = buffer_read_char(input);
	}

	if (buf[size-2] == '\r' && buf[size-1] == '\n')
		buf[size-2] = '\0';
	else if (buf[size-1] == '\n')
		buf[size-1] = '\0';

	if (strncmp(buf, "ls", 2) == 0) {
		buffer_append_string(output, run_cmd("ls"));
	} else if (strncmp(buf, "pwd", 3) == 0) {
		char buf[256] = {0};
		buffer_append_string(output, getcwd(buf, 256));
	} else if (strncmp(buf, "cd ", 3) == 0) {
		char target[256];
		bzero(target, sizeof(target));
		memcpy(target, buf + 3, strlen(buf) - 3);
		if (chdir(target) == -1) {
			printf("change dir failed, %s\n", target);
		}
	} else {
		char *error = "error: unknown input type";
		buffer_append_string(output, error);
	}
	
	buffer_append_char(output, '\n');
	tcp_connection_send_buffer(tcpConnection, output);
	return 0;
}

int onWriteCompleted(struct tcp_connection *tcpConnection) {
	printf("write completed\n");
	return 0;
}

int onConnectionClosed(struct tcp_connection *tcpConnection) {
	printf("connection closed\n");
	return 0;
}

int main(int argc, char **argv) {
	struct event_loop *eventLoop = event_loop_init();

	struct acceptor *acceptor = acceptor_init(SERV_PORT);

	struct TCPserver *tcpServer = tcp_server_init(eventLoop, acceptor, onConnectionCompleted, onMessage, 
			onWriteCompleted, onConnectionClosed, 0);

	tcp_server_start(tcpServer);

	event_loop_run(eventLoop);
}
