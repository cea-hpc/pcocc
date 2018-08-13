package command


import (
	"sync"
	"time"
	"os"
	"path/filepath"
	"os/exec"
	"io"
	"syscall"
	"agent_protocol"
	"errors"
	"os/user"
	"strconv"
	log "github.com/sirupsen/logrus"
	proto "github.com/golang/protobuf/proto"
	ptypes "github.com/golang/protobuf/ptypes"
)

type Dispatch struct {
	Inc  chan *agent_protocol.AgentMessage
	Outc chan *agent_protocol.AgentMessage
	SimpleFuncMap map[string]func(proto.Message)(proto.Message)
	StreamFuncMap map[string]func(proto.Message, string, int64)
	ExMan *ExecManager
	wg      sync.WaitGroup
}

type ExecManager struct {
	Execs   map[int64]*AgentExec
	Outc    chan *agent_protocol.AgentMessage
	Lock    *sync.Mutex
	// Whether we are currently detaching clients across all
	// execs for a freeze
	isDetaching  bool
	// Number of attached execs
	attachCount  int
	// Set when all attached execs have exited
	allDetached  *sync.Cond
}

type AgentExec struct {
	id               int64
	cmd              *exec.Cmd
	filename         string
	args             []string

	manager          *ExecManager

	eofCount         int
	// Whether the process exit has been seen
	isExited         bool
	// Whether a reader is attached
	isAttached       bool
	// Whether events can still be sent to the handler
	isValid          bool
	// Whether all clients have been served
	isDrained        bool
	// Tag of the attached reader
	curTag          int64

	// Signal the eventhandler of attach/detach/abort
	eventChan       chan struct{int; int64}
	// Send IO messages from pipes to the eventhandler
	outChan         chan *agent_protocol.IOMessage
	// Send Agent Messages back to the host agent
	agentChan       chan *agent_protocol.AgentMessage

	// Pipes to the process stdio
	stdinPipe       io.WriteCloser
	stdoutPipe      io.ReadCloser
	stderrPipe      io.ReadCloser

	// Allow eventhandler to wait for last clients
	clientLock           sync.Mutex
	clientwg             sync.WaitGroup
}

func MakeDispatch(inc chan *agent_protocol.AgentMessage, outc chan *agent_protocol.AgentMessage) *Dispatch {
	ret := new(Dispatch)
	ret.Inc = inc
	ret.Outc = outc

	ret.SimpleFuncMap = map[string]func(proto.Message)(proto.Message){
		"freeze":     ret.handleFreezeMessage,
		"thaw":       ret.handleThawMessage,
		"hello":      ret.handleHelloMessage,
		"hostname":   ret.handleHostnameMessage,
		"mkdir":      ret.handleMkdirMessage,
		"chmod":      ret.handleChmodMessage,
		"chown":      ret.handleChownMessage,
		"truncate":   ret.handleTruncateMessage,
		"stat":       ret.handleStatMessage,
		"symlink":    ret.handleSymlinkMessage,
		"move":       ret.handleMoveMessage,
		"remove":     ret.handleRemoveMessage,
		"execve":     ret.handleExecMessage,
		"stdin":      ret.handleStdinMessage,
		"detach":     ret.handleDetachMessage,
		"kill":       ret.handleKillMessage,
		"writefile":  ret.handleWriteFileMessage,
		"listexec":   ret.handleListExecMessage,
	}

	ret.StreamFuncMap = map[string]func(proto.Message, string, int64)(){
		"attach":   ret.handleAttachMessage,
	}

	ret.ExMan = MakeExecManager(outc)
	return ret
}

func MakeExecManager(outc chan *agent_protocol.AgentMessage) *ExecManager {
	ret := new(ExecManager)
	ret.Execs = make(map[int64]*AgentExec)
	ret.Outc = outc
	ret.Lock  = new(sync.Mutex)
	ret.allDetached  =  sync.NewCond(ret.Lock)
	return ret
}


func messageReplyKind(stream bool) (agent_protocol.AgentMessage_MsgKind){
	if stream {
		return agent_protocol.AgentMessage_StreamReply
	} else {
		return agent_protocol.AgentMessage_Reply
	}
}

func (cd *Dispatch) sendReply(tag int64, name string, stream bool, msg proto.Message) {
	var err error

	reply := new(agent_protocol.AgentMessage)
	reply.Tag = tag
	reply.Kind = messageReplyKind(stream)
	reply.Name = name
	reply.Data, err = ptypes.MarshalAny(msg)

	if err != nil {
		log.Error("Could not pack message reply: ", err)
		reply.Data, _  = ptypes.MarshalAny(errorMessage(errors.New("Could not pack message reply")))
	}
	if !stream {
		cd.wg.Done()
	}

	cd.Outc <- reply
}


func (cd *Dispatch) processStreamMessage(msg *agent_protocol.AgentMessage){
	f, exists := cd.StreamFuncMap[msg.Name]
	if !exists {
		cd.sendReply(msg.Tag, msg.Name, false,
			errorMessage(errors.New("Unknown stream message name "+ msg.Name)))
		return
	}

	data, err := ptypes.Empty(msg.Data)
	if err != nil {
		cd.sendReply(msg.Tag, msg.Name, false,
			errorMessage(errors.New("Could not handle stream message data")))
		return
	}

	ptypes.UnmarshalAny(msg.Data, data)
	log.Info("Handling message", msg.Name," stream request")
	f(data, msg.Name, msg.Tag)
}


func (cd *Dispatch) processSimpleMessage(msg *agent_protocol.AgentMessage){
	f, exists := cd.SimpleFuncMap[msg.Name]
	if !exists {
		cd.sendReply(msg.Tag, msg.Name, false,
			errorMessage(errors.New("Unknown message name: " + msg.Name)))
		return
	}

	data, err := ptypes.Empty(msg.Data)
	if err != nil {
		cd.sendReply(msg.Tag, msg.Name, false,
			errorMessage(errors.New("Could not handle message data")))
		return
	}

	ptypes.UnmarshalAny(msg.Data, data)
	log.Info("Handling ", msg.Name," unary request")
	cd.sendReply(msg.Tag, msg.Name, false, f(data))
}

func (cd *Dispatch) Run() {
	for msg := range cd.Inc {
		switch msg.Kind {
		case agent_protocol.AgentMessage_Request:
			cd.wg.Add(1)
			go cd.processSimpleMessage(msg)
		case agent_protocol.AgentMessage_StreamRequest:
			cd.wg.Add(1)
			go cd.processStreamMessage(msg)
		default:
			log.Error("Ignoring unexpected message type")
		}
	}

	log.Info("Input channel closed, waiting for last replies")
	cd.wg.Wait()
	log.Info("Terminating dispatcher")
	close(cd.Outc)

	return
}

func errorMessage(err error) (proto.Message) {
	log.Debug("returning error to host agent: ", err.Error())
	ret := new(agent_protocol.GenericError)
	ret.Kind = agent_protocol.GenericError_AgentError
	ret.Description = err.Error()
	return ret
}

func (cd *Dispatch)  handleThawMessage(data proto.Message) (proto.Message) {
	return new(agent_protocol.ThawResult)
}

func (cd *Dispatch) handleHelloMessage(data proto.Message) (proto.Message) {
	ret := new(agent_protocol.HelloResult)
	ret.Version = 1
	ret.Epoch = time.Now().Unix()

	return ret
}

func (cd *Dispatch) handleFreezeMessage(data proto.Message) (proto.Message) {
	cd.ExMan.detachAllExecs()
	return new(agent_protocol.FreezeResult)
}

func (cd *Dispatch) handleHostnameMessage(data proto.Message) (proto.Message) {
	hostname, err := os.Hostname()
	if err != nil {
		return errorMessage(err)
	}

	ret := new(agent_protocol.HostnameResult)
	ret.Hostname = hostname

	return ret
}

func (cd *Dispatch) handleMkdirMessage(data proto.Message) (proto.Message) {
	var err error

	msg := data.(*agent_protocol.MkdirMessage)
	mode := os.FileMode(msg.Mode)

	if msg.MakeParent{
		err = os.MkdirAll(msg.Path, mode)
	} else {
		err = os.Mkdir(msg.Path, mode)
	}

	if err != nil {
		return errorMessage(err)
	}

	return new(agent_protocol.MkdirResult)
}

func (cd *Dispatch) handleChmodMessage(data proto.Message) (proto.Message) {
	var err error

	msg := data.(*agent_protocol.ChmodMessage)
	mode := os.FileMode(msg.Mode)

	if msg.Recurse {
		err = filepath.Walk(msg.Path,
			func(name string, info os.FileInfo, err error) error {
				if err == nil {
					err = os.Chmod(name, mode)
				}
				return err
			})
	} else {
		err = os.Chmod(msg.Path, mode)
	}

	if err != nil {
		return errorMessage(err)
	}

	return new(agent_protocol.ChmodResult)
}

func (cd *Dispatch) handleChownMessage(data proto.Message) (proto.Message) {
	var err error

	msg := data.(*agent_protocol.ChownMessage)
	if msg.Recurse {
		err = filepath.Walk(msg.Path,
			func(name string, info os.FileInfo, err error) error {
				if err == nil {
					err = os.Chown(name, int(msg.Uid), int(msg.Gid))
				}
				return err
			})
	} else {
		err = os.Chown(msg.Path, int(msg.Uid), int(msg.Gid))
	}

	if err != nil {
		return errorMessage(err)
	}

	return new(agent_protocol.ChownResult)
}

func (cd *Dispatch) handleSymlinkMessage(data proto.Message) (proto.Message) {
	var err error

	msg := data.(*agent_protocol.SymlinkMessage)

	err = os.Symlink(msg.Src, msg.Dst)

	if err != nil {
		return errorMessage(err)
	}

	return new(agent_protocol.SymlinkResult)
}

func (cd *Dispatch) handleRemoveMessage(data proto.Message) (proto.Message) {
	var err error
	msg := data.(*agent_protocol.RemoveMessage)


	if msg.Recurse{
		err = os.RemoveAll(msg.Path)
	} else {
		err = os.Remove(msg.Path)
	}

	if err != nil {
		return errorMessage(err)
	}

	return new(agent_protocol.RemoveResult)
}

func (cd *Dispatch) handleMoveMessage(data proto.Message) (proto.Message) {
	var err error

	msg := data.(*agent_protocol.MoveMessage)

	err = os.Rename(msg.Src, msg.Dst)

	if err != nil {
		return errorMessage(err)
	}

	return new(agent_protocol.MoveResult)
}

func (cd *Dispatch) handleTruncateMessage(data proto.Message) (proto.Message) {
	var err error

	msg := data.(*agent_protocol.TruncateMessage)

	err = os.Truncate(msg.Path, msg.Size)

	if err != nil {
		return errorMessage(err)
	}

	return new(agent_protocol.TruncateResult)
}

func (cmd *Dispatch) handleStatMessage(data proto.Message) (proto.Message) {
	var err error

	msg := data.(*agent_protocol.StatMessage)

	stat, err := os.Stat(msg.Path)
	if err != nil {
		return  errorMessage(err)
	}

	modtime, err :=ptypes.TimestampProto(stat.ModTime())
	if err != nil {
		return  errorMessage(err)
	}

	ret := new(agent_protocol.StatResult)

	ret.Size    = stat.Size()
	ret.Name    = stat.Name()
	ret.Mode    = int32(stat.Mode().Perm())
	ret.ModTime = modtime
	ret.IsDir   = stat.IsDir()

	return ret
}

func (ex *AgentExec) log() (*log.Entry) {
	return log.WithFields(log.Fields{
		"cmd":    ex.filename,
		"execid": ex.id})
}

func (ex *AgentExec) pipeReader(ioKind agent_protocol.IOMessage_MsgKind, s io.ReadCloser) {
	var b = make([]byte, 32768)
	var err error
	var n int

	ex.log().Info("pipeReader started")
	for err != io.EOF {
		n, err = s.Read(b)

		if n == 0 && err != io.EOF {
			// Should we relay these errors?
			ex.log().Error(err)
			continue
		}

		var msg = new(agent_protocol.IOMessage)
		msg.Kind = ioKind
		msg.Data = make([]byte, n)
		copy(msg.Data, b[:n])
		if err == io.EOF {
			msg.Eof = true
		}
		// TODO: We could try to send messages aligned on \n
		// boudaries to make it easier for the client to
		// multiplex streams from several sources
		ex.log().Debug("pipeReader read: ", string(msg.Data), " from process")
		ex.outChan <- msg
	}
	ex.log().Info("pipeReader: exiting after EOF")
}

func (em *ExecManager) recordAttach() error {
	em.Lock.Lock()
	defer em.Lock.Unlock()
	if em.isDetaching {
		return errors.New("Unable to attach in the current state")
	}
	em.attachCount++

	return nil
}

func (em *ExecManager) recordDetach() error {
	em.Lock.Lock()
	defer em.Lock.Unlock()
	em.attachCount--
	if em.attachCount == 0 {
		em.isDetaching = false
		em.allDetached.Broadcast()
	}
	return nil
}


func (em *ExecManager) getExec(id int64) (*AgentExec, error) {
	em.Lock.Lock()
	ex, exists := em.Execs[id]
	em.Lock.Unlock()

	if ! exists {
		return nil, errors.New("No current exec with this id")
	}

	return ex, nil
}

func (em *ExecManager) sendInputExec(id int64, data []byte, eof bool) (int, error) {
	ex, err := em.getExec(id)
	if err != nil {
		return 0, err
	}

	n, err := ex.stdinPipe.Write(data)
	if eof {
		ex.stdinPipe.Close()
	}

	return n, err
}

func (em *ExecManager) attachExec(id int64, tag int64) (error) {
	ex, err := em.getExec(id)
	if err != nil {
		return err
	}

	err = ex.getEventChan()
	if err != nil {
		return err
	}

	ex.log().Debug("Attaching")
	ex.eventChan <- struct {int; int64}{ATTACHED, tag}
	ex.putEventChan()
	return nil
}

func (em *ExecManager) getAllExecs() (map[int64]*AgentExec) {
	em.Lock.Lock()
	defer em.Lock.Unlock()

	execs := make(map[int64]*AgentExec)
	for k, e := range em.Execs {
		execs[k]= e
	}

	return execs
}
func (em *ExecManager) detachAllExecs() (error) {
	var best_err error
	em.Lock.Lock()
	defer em.Lock.Unlock()

	if !em.isDetaching {
		em.isDetaching = true
		for _, ex := range em.Execs {
			// We cant hold the lock here because it's
			// needed for the detach. It's fine though since
			// nobody new will be attaching now that we set isDetaching
			em.Lock.Unlock()
			err := ex.detach(0)
			em.Lock.Lock()
			if err != nil && best_err == nil {
				best_err = err
			}
		}
	}

	// Make sure we dont wait if the condition has been met
	// when we released locks
	if em.isDetaching && em.attachCount > 0 {
		em.allDetached.Wait()
	}

	return best_err
}

func (em *ExecManager) detachExec(id int64,  tag int64) (error) {
	ex, err := em.getExec(id)
	if err != nil {
		return err
	}
	return ex.detach(tag)
}

func (em *ExecManager) killExec(id int64) (error) {
	ex, err := em.getExec(id)
	if err != nil {
		return err
	}

	if err := ex.cmd.Process.Kill(); err != nil {
		return err
	}
	ex.log().Debug("Kill signal sent")
	return nil
}

func (em *ExecManager) registerExec(id int64, filename string, args []string, env []string, username string) (error) {
	em.Lock.Lock()
	defer em.Lock.Unlock()

	_, exists := em.Execs[id]
	if exists {
		return errors.New("Unable to register exec: id already in use")
	}

	newExec := new(AgentExec)
	newExec.manager                    = em
	newExec.id                         = id
	newExec.filename                   = filename
	newExec.args                       = args
	newExec.cmd                        = exec.Command(filename, args...)
	newExec.cmd.SysProcAttr            = &syscall.SysProcAttr{Setpgid: true}

	if username == "" {
		username = "root"
	}

	u, err := user.Lookup(username)
	if err != nil {
		return err
	}
	uid, _ := strconv.Atoi(u.Uid)
        gid, _ := strconv.Atoi(u.Gid)

	newExec.cmd.SysProcAttr.Credential = &syscall.Credential{
		Uid: uint32(uid),
		Gid: uint32(gid)}

	if len(env) > 0  {
		newExec.cmd.Env = env
	}


	newExec.stdinPipe, err  = newExec.cmd.StdinPipe()
	if err != nil {
		return err
	}
	newExec.stdoutPipe, err = newExec.cmd.StdoutPipe()
	if err != nil {
		return err
	}
	newExec.stderrPipe, err = newExec.cmd.StderrPipe()
	if err != nil {
		return err
	}

	if err := newExec.cmd.Start(); err != nil {
		return err
	}

	newExec.outChan   = make(chan *agent_protocol.IOMessage)
	newExec.eventChan = make(chan struct {int; int64})
	newExec.agentChan = em.Outc

	// Aggregate from exec pipes to eventHandler
	go newExec.pipeReader(agent_protocol.IOMessage_stdout, newExec.stdoutPipe)
	go newExec.pipeReader(agent_protocol.IOMessage_stderr, newExec.stderrPipe)

	// Centralize all events (IO, attach, exit...) related to this exec
	go newExec.eventHandler()
	newExec.isValid = true

	em.Execs[id] = newExec

	log.Debug("new exec registered: now ", len(em.Execs), "active execs")

	return nil
}

const (
        ATTACHED = iota
        DETACHED = iota
	EXITED  = iota
	DRAINED  = iota
)

func (ex *AgentExec) getEventChan() (error) {
	ex.clientLock.Lock()
	defer ex.clientLock.Unlock()

	if !ex.isValid {
		ex.log().Info("Failed to acquire event channel")
		return errors.New("No current exec with this id")
	}
	ex.clientwg.Add(1)
	ex.log().Debug("Acquired event channel")
	return nil
}

func (ex *AgentExec) putEventChan() () {
	ex.clientwg.Done()
	ex.log().Debug("Released event channel")
}

func (ex *AgentExec) detach(tag int64) error {
	err:= ex.getEventChan()
	if err != nil {
		return err
	}

	ex.log().Debug("Detaching")
	ex.eventChan <- struct {int; int64}{DETACHED, tag}
	ex.putEventChan()
	return nil
}

func (ex *AgentExec) execReaper() {
	ex.log().Debug("execReaper waiting for task exit")
	ex.cmd.Wait()
	ex.log().Debug("execReaper noticed task exit ")
	ex.eventChan <-	struct {int; int64}{EXITED, 0}
	ex.log().Debug("execReaper notified eventHandler")
}

func (ex *AgentExec) handleEventChan(event int, tag int64)  {
	switch event {
	case ATTACHED:
		if ! ex.isValid {
			ex.sendOutMessage(tag, false,
				errorMessage(errors.New(
					"No current exec with this id")))
			return
		}
		if ex.isAttached{
			ex.log().Warning("Attach event while already attached")
	                ex.log().Warning("Detaching previous reader")
			ex.sendOutMessage(ex.curTag, false, new(agent_protocol.DetachResult))
		} else {
			err := ex.manager.recordAttach()
			if err != nil {
				ex.sendOutMessage(tag, false, errorMessage(err))
				return
			}
		}
		ex.log().Debug("Now in attached mode")
		ex.isAttached = true
		ex.curTag = tag
		ex.sendOutMessage(tag, true, new(agent_protocol.AttachResult))
	case DETACHED:
		if !ex.isAttached{
			ex.log().Info("Detach event while already detached")
			return
		} else if tag != 0 && tag != ex.curTag {
			ex.log().Info("Detach for non current reader")
			return
		}
		ex.log().Debug("Now in detached mode")
		ex.manager.recordDetach()
		ex.sendOutMessage(ex.curTag, false, new(agent_protocol.DetachResult))
		ex.isAttached = false
	case EXITED:
		ex.isExited = true
	case DRAINED:
		ex.isDrained = true
	}
}

func (ex *AgentExec) sendOutMessage(tag int64, stream bool, msg proto.Message) {
	//FIXME: call dispatch sendreply
	var err error

	reply := new(agent_protocol.AgentMessage)
	reply.Tag = tag
	reply.Kind = messageReplyKind(stream)
	reply.Name = "attach"
	reply.Data, err = ptypes.MarshalAny(msg)
	if err != nil {
		ex.log().Error("Could not pack AgentExec message: ", err)
		reply.Data, _ = ptypes.MarshalAny(
			errorMessage(errors.New("Could not pack message reply")))
	}

	ex.log().Debug("AgentExec pushing message ", reply.Name, " to agent")
	ex.agentChan <- reply
}
func (ex *AgentExec) clientReaper() {
	ex.log().Debug("Waiting for eventChan clients")
	ex.clientwg.Wait()
	ex.log().Debug("All clients complete, signalling eventHandler ")
	ex.eventChan <- struct {int; int64}{DRAINED, 0}
}

func (ex *AgentExec) eventHandler() {
	for {
		if ex.isAttached {
			if ex.isExited {
				var msg = new(agent_protocol.ExitStatus)
				msg.Status = int32(ex.cmd.ProcessState.Sys().(syscall.WaitStatus).ExitStatus())
				ex.log().Debug("eventHandler: sending exit code", msg.Status)
				ex.sendOutMessage(ex.curTag, false, msg)
				ex.isAttached = false
				ex.manager.recordDetach()
				break
			}

			select {
			case execEvent := <-ex.eventChan:
				ex.handleEventChan(execEvent.int, execEvent.int64)
			case data := <- ex.outChan:
				if data.Eof {
					// We want to read all data before having the reaper call
					// Wait on the command
					ex.eofCount++
					if ex.eofCount == 2 {
						go ex.execReaper()
					}
				}
				ex.sendOutMessage(ex.curTag, true, data)
			}
		} else {
			// When not attached, dont read from pipes,
			// wait for an attach event
			execEvent:= <-ex.eventChan
			ex.handleEventChan(execEvent.int, execEvent.int64)
		}
	}

	ex.clientLock.Lock()
	ex.isValid = false
	ex.clientLock.Unlock()

	// At this point no new client should start using our event
	// chan and those who have started are accounted for in the
	// waitgroup. The reaper uses the waitgroup to wait for those
	// who have already started which we serve concurrently by
	// handling the eventchan below
	go ex.clientReaper()
	for ex.isDrained == false {
		execEvent:= <- ex.eventChan
		ex.handleEventChan(execEvent.int, execEvent.int64)
	}

	ex.manager.Lock.Lock()
	delete(ex.manager.Execs, ex.id)
	ex.manager.Lock.Unlock()
}


func (cd *Dispatch) handleExecMessage(data proto.Message) (proto.Message) {
	var err error

	msg := data.(*agent_protocol.ExecMessage)
	err = cd.ExMan.registerExec(msg.ExecId, msg.Filename, msg.Args, msg.Env, msg.Username)
	if err != nil {
		return errorMessage(err)
	}

	return new(agent_protocol.ExecResult)
}

func (cd *Dispatch) handleAttachMessage(data proto.Message, name string, tag int64) () {
	var err error

	msg := data.(*agent_protocol.AttachMessage)
	err = cd.ExMan.attachExec(msg.ExecId, tag)
	if err != nil {
		cd.sendReply(tag, name, false, errorMessage(err))
	}
}

func (cd *Dispatch) handleStdinMessage(data proto.Message) (proto.Message) {
	var err error

	msg := data.(*agent_protocol.IOMessage)
	_, err = cd.ExMan.sendInputExec(msg.ExecId, msg.Data, msg.Eof)
	if err != nil {
		// FIXME: Do we need a better error with the number of
		// written bytes ?
		return errorMessage(err)
	}

	return new(agent_protocol.IOResult)
}

func (cd *Dispatch) handleDetachMessage(data proto.Message) (proto.Message) {
	var err error

	msg := data.(*agent_protocol.DetachMessage)
	err = cd.ExMan.detachExec(msg.ExecId, msg.Tag)
	if err != nil {
		return errorMessage(err)
	}

	return new(agent_protocol.DetachResult)
}

func (cd *Dispatch) handleKillMessage(data proto.Message) (proto.Message) {
	var err error

	msg := data.(*agent_protocol.KillMessage)
	err = cd.ExMan.killExec(msg.ExecId)
	if err != nil {
		return errorMessage(err)
	}

	return new(agent_protocol.KillResult)
}

func (cd *Dispatch) handleListExecMessage(data proto.Message) (proto.Message) {
	execs := cd.ExMan.getAllExecs()

	reply := new(agent_protocol.ListExecResult)
	reply.Execs = make(map[int64]*agent_protocol.ExecInfo)
	for k, e := range execs {
		reply.Execs[k] =  &agent_protocol.ExecInfo {
			Filename: e.filename,
			Attached: e.isAttached,
			Running: !e.isExited,
		}
	}

	return reply
}

func (cmd *Dispatch) handleWriteFileMessage(data proto.Message) (proto.Message) {
	var f *os.File
	var err error
	msg := data.(*agent_protocol.WriteFileMessage)

	if msg.Append {
		f, err = os.OpenFile(msg.Path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, os.FileMode(msg.Perms))
	} else {
		f, err = os.OpenFile(msg.Path, os.O_TRUNC|os.O_CREATE|os.O_WRONLY, os.FileMode(msg.Perms))
	}

	if err != nil {
		return errorMessage(err)
	}

	defer f.Close()
	n, err := f.Write(msg.Data)
	if err != nil {
		return errorMessage(err)
	}

	ret := new(agent_protocol.WriteFileResult)
	ret.Written = int64(n)

	return ret
}
