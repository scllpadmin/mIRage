import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Search, 
  Settings, 
  Users, 
  Database, 
  Activity, 
  FileText, 
  AlertTriangle, 
  Lock, 
  Globe, 
  Server, 
  Package, 
  GitBranch,
  MessageSquare,
  BarChart3,
  Eye,
  Plus,
  Download,
  Upload,
  Play,
  Pause,
  RefreshCw,
  CheckCircle,
  XCircle,
  Clock,
  User,
  LogOut,
  Home,
  Layers,
  Target,
  Zap,
  ArrowLeft
} from 'lucide-react';

const mIRage = () => {
  const [currentPage, setCurrentPage] = useState('dashboard');
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [user, setUser] = useState({ name: 'Administrator', role: 'admin' });
  const [modules, setModules] = useState([
    { id: 1, name: 'MISP Enrichment', status: 'active', version: '2.1.0', description: 'IOC enrichment via MISP' },
    { id: 2, name: 'VirusTotal', status: 'active', version: '1.5.2', description: 'Malware analysis and IOC lookup' },
    { id: 3, name: 'Splunk Connector', status: 'inactive', version: '3.0.1', description: 'Log ingestion to Splunk SIEM' },
    { id: 4, name: 'EVTX Parser', status: 'active', version: '2.3.0', description: 'Windows Event Log processing' }
  ]);
  const [cases, setCases] = useState([
    { id: 1, name: 'Phishing Campaign Alpha', status: 'active', severity: 'high', assignee: 'John Doe', created: '2025-08-01' },
    { id: 2, name: 'Ransomware Investigation', status: 'closed', severity: 'critical', assignee: 'Jane Smith', created: '2025-07-28' },
    { id: 3, name: 'Data Exfiltration Incident', status: 'active', severity: 'medium', assignee: 'Mike Johnson', created: '2025-08-05' }
  ]);
  
  const [playbooks, setPlaybooks] = useState([
    { id: 1, name: 'Incident Response Standard', status: 'active', tasks: 12, version: '2.1.0', created: '2025-07-15' },
    { id: 2, name: 'Malware Analysis Protocol', status: 'active', tasks: 8, version: '1.5.0', created: '2025-06-20' },
    { id: 3, name: 'Data Breach Investigation', status: 'draft', tasks: 15, version: '3.0.0', created: '2025-08-01' }
  ]);
  
  const [selectedTasks, setSelectedTasks] = useState([]);
  const [showBulkActions, setShowBulkActions] = useState(false);

  // Login component
  const LoginPage = () => (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 via-purple-900 to-indigo-900 flex items-center justify-center p-4">
      <div className="max-w-md w-full space-y-8">
        <div className="text-center">
          <div className="flex justify-center mb-6">
            <div className="w-20 h-20 bg-gradient-to-br from-purple-400 to-blue-500 rounded-xl flex items-center justify-center">
              <Shield className="w-10 h-10 text-white" />
            </div>
          </div>
          <h2 className="text-4xl font-bold text-white mb-2">mIRage</h2>
          <p className="text-gray-300">Digital Forensics & Incident Response Platform</p>
        </div>
        
        <div className="bg-white/10 backdrop-blur-lg rounded-xl p-8 shadow-2xl border border-white/20">
          <div className="space-y-6">
            <div>
              <label className="block text-sm font-medium text-gray-200 mb-2">Username</label>
              <input
                type="text"
                defaultValue="administrator"
                className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-400 focus:ring-2 focus:ring-blue-400/20"
                placeholder="Enter username"
              />
            </div>
            
            <div>
              <label className="block text-sm font-medium text-gray-200 mb-2">Password</label>
              <input
                type="password"
                className="w-full px-4 py-3 bg-white/10 border border-white/20 rounded-lg text-white placeholder-gray-400 focus:outline-none focus:border-blue-400 focus:ring-2 focus:ring-blue-400/20"
                placeholder="Enter password"
              />
            </div>
            
            <button
              onClick={() => {
                setIsLoggedIn(true);
                setCurrentPage('dashboard');
              }}
              className="w-full bg-gradient-to-r from-blue-500 to-purple-600 hover:from-blue-600 hover:to-purple-700 text-white font-semibold py-3 px-4 rounded-lg transition-all duration-200 transform hover:scale-105"
            >
              Sign In
            </button>
          </div>
          
          <div className="mt-6 text-center">
            <p className="text-xs text-gray-400">
              Default credentials: administrator / (check Docker logs for initial password)
            </p>
          </div>
        </div>
      </div>
    </div>
  );

  // Navigation component
  const Navigation = () => (
    <nav className="bg-gray-900 text-white p-4 border-b border-gray-700">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-6">
          <div className="flex items-center space-x-2">
            <Shield className="w-8 h-8 text-blue-400" />
            <span className="text-2xl font-bold bg-gradient-to-r from-blue-400 to-purple-400 bg-clip-text text-transparent">
              mIRage
            </span>
          </div>
          
          <div className="flex space-x-1">
            {[
              { id: 'dashboard', label: 'Dashboard', icon: Home },
              { id: 'cases', label: 'Cases', icon: FileText },
              { id: 'playbooks', label: 'Playbooks', icon: Layers },
              { id: 'iocs', label: 'IOCs', icon: Target },
              { id: 'integrations', label: 'Integrations', icon: Zap },
              { id: 'modules', label: 'Modules', icon: Package },
              { id: 'users', label: 'Users', icon: Users },
              { id: 'settings', label: 'Settings', icon: Settings }
            ].map(({ id, label, icon: Icon }) => (
              <button
                key={id}
                onClick={() => setCurrentPage(id)}
                className={`px-4 py-2 rounded-lg flex items-center space-x-2 transition-colors ${
                  currentPage === id 
                    ? 'bg-blue-600 text-white' 
                    : 'text-gray-300 hover:text-white hover:bg-gray-700'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{label}</span>
              </button>
            ))}
          </div>
        </div>
        
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2">
            <User className="w-5 h-5 text-gray-400" />
            <span className="text-sm">{user.name}</span>
          </div>
          <button
            onClick={() => setIsLoggedIn(false)}
            className="p-2 text-gray-400 hover:text-white transition-colors"
          >
            <LogOut className="w-5 h-5" />
          </button>
        </div>
      </div>
    </nav>
  );

  // Dashboard page
  const Dashboard = () => (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold text-gray-900 flex items-center space-x-3">
        <BarChart3 className="w-8 h-8 text-blue-600" />
        <span>Dashboard</span>
      </h1>
      
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        {[
          { title: 'Active Cases', value: '3', icon: FileText, color: 'blue' },
          { title: 'Active Playbooks', value: '2', icon: Layers, color: 'green' },
          { title: 'Critical IOCs', value: '27', icon: AlertTriangle, color: 'red' },
          { title: 'Active Modules', value: '3', icon: Package, color: 'purple' }
        ].map((stat, index) => (
          <div key={index} className="bg-white rounded-xl shadow-lg p-6 border-l-4 border-blue-500">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">{stat.title}</p>
                <p className="text-3xl font-bold text-gray-900">{stat.value}</p>
              </div>
              <div className={`p-3 bg-${stat.color}-100 rounded-lg`}>
                <stat.icon className={`w-6 h-6 text-${stat.color}-600`} />
              </div>
            </div>
          </div>
        ))}
      </div>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-xl shadow-lg p-6">
          <h3 className="text-xl font-semibold text-gray-900 mb-4">Recent Cases</h3>
          <div className="space-y-3">
            {cases.slice(0, 3).map(case_ => (
              <div key={case_.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div>
                  <p className="font-medium text-gray-900">{case_.name}</p>
                  <p className="text-sm text-gray-600">{case_.assignee} • {case_.created}</p>
                </div>
                <div className={`px-2 py-1 rounded-full text-xs font-medium ${
                  case_.status === 'active' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                }`}>
                  {case_.status}
                </div>
              </div>
            ))}
          </div>
        </div>
        
        <div className="bg-white rounded-xl shadow-lg p-6">
          <h3 className="text-xl font-semibold text-gray-900 mb-4">Module Status</h3>
          <div className="space-y-3">
            {modules.map(module => (
              <div key={module.id} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                <div>
                  <p className="font-medium text-gray-900">{module.name}</p>
                  <p className="text-sm text-gray-600">v{module.version}</p>
                </div>
                <div className={`w-3 h-3 rounded-full ${
                  module.status === 'active' ? 'bg-green-500' : 'bg-gray-400'
                }`} />
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );

  // Cases page
  const Cases = () => (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900 flex items-center space-x-3">
          <FileText className="w-8 h-8 text-blue-600" />
          <span>Cases</span>
        </h1>
        <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2">
          <Plus className="w-4 h-4" />
          <span>New Case</span>
        </button>
      </div>
      
      <div className="bg-white rounded-xl shadow-lg overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Case Name</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Severity</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Assignee</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Created</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {cases.map(case_ => (
              <tr key={case_.id} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{case_.name}</td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                    case_.status === 'active' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                  }`}>
                    {case_.status}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                    case_.severity === 'critical' ? 'bg-red-100 text-red-800' :
                    case_.severity === 'high' ? 'bg-orange-100 text-orange-800' : 'bg-yellow-100 text-yellow-800'
                  }`}>
                    {case_.severity}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{case_.assignee}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{case_.created}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  <button className="text-blue-600 hover:text-blue-900 mr-3">View</button>
                  <button className="text-indigo-600 hover:text-indigo-900">Edit</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  // Playbooks page with bulk operations
  const Playbooks = () => {
    const [currentPlaybook, setCurrentPlaybook] = useState(null);
    const [tasks, setTasks] = useState([
      { id: 1, name: 'Initial Assessment', status: 'completed', priority: 'high', assignee: 'John Doe', estimated: 30 },
      { id: 2, name: 'Evidence Collection', status: 'in_progress', priority: 'critical', assignee: 'Jane Smith', estimated: 120 },
      { id: 3, name: 'Network Analysis', status: 'pending', priority: 'medium', assignee: null, estimated: 90 },
      { id: 4, name: 'Malware Analysis', status: 'pending', priority: 'high', assignee: 'Mike Johnson', estimated: 180 },
      { id: 5, name: 'Timeline Creation', status: 'pending', priority: 'medium', assignee: null, estimated: 60 },
      { id: 6, name: 'Report Generation', status: 'pending', priority: 'low', assignee: null, estimated: 45 }
    ]);
    
    const handleTaskSelect = (taskId) => {
      setSelectedTasks(prev => 
        prev.includes(taskId) 
          ? prev.filter(id => id !== taskId)
          : [...prev, taskId]
      );
    };
    
    const handleSelectAll = () => {
      if (selectedTasks.length === tasks.length) {
        setSelectedTasks([]);
      } else {
        setSelectedTasks(tasks.map(t => t.id));
      }
    };
    
    const handleBulkAssign = (assigneeId, assigneeName) => {
      setTasks(prev => prev.map(task => 
        selectedTasks.includes(task.id) 
          ? { ...task, assignee: assigneeName }
          : task
      ));
      setSelectedTasks([]);
      setShowBulkActions(false);
    };
    
    const handleBulkStatusUpdate = (newStatus) => {
      setTasks(prev => prev.map(task => 
        selectedTasks.includes(task.id) 
          ? { ...task, status: newStatus }
          : task
      ));
      setSelectedTasks([]);
      setShowBulkActions(false);
    };
    
    const handleBulkPriorityUpdate = (newPriority) => {
      setTasks(prev => prev.map(task => 
        selectedTasks.includes(task.id) 
          ? { ...task, priority: newPriority }
          : task
      ));
      setSelectedTasks([]);
      setShowBulkActions(false);
    };

    if (currentPlaybook) {
      return (
        <div className="p-6 space-y-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <button 
                onClick={() => setCurrentPlaybook(null)}
                className="p-2 hover:bg-gray-100 rounded-lg"
              >
                <ArrowLeft className="w-5 h-5" />
              </button>
              <div>
                <h1 className="text-3xl font-bold text-gray-900 flex items-center space-x-3">
                  <Layers className="w-8 h-8 text-blue-600" />
                  <span>{currentPlaybook.name}</span>
                </h1>
                <p className="text-gray-600">Version {currentPlaybook.version} • {tasks.length} tasks</p>
              </div>
            </div>
            
            {selectedTasks.length > 0 && (
              <div className="flex items-center space-x-2">
                <span className="text-sm text-gray-600">{selectedTasks.length} selected</span>
                <button
                  onClick={() => setShowBulkActions(!showBulkActions)}
                  className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2"
                >
                  <Zap className="w-4 h-4" />
                  <span>Bulk Actions</span>
                </button>
              </div>
            )}
          </div>
          
          {/* Bulk Actions Panel */}
          {showBulkActions && (
            <div className="bg-white rounded-xl shadow-lg p-6 border-l-4 border-blue-500">
              <h3 className="text-lg font-semibold text-gray-900 mb-4">Bulk Actions</h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Assign To</label>
                  <select 
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"
                    onChange={(e) => {
                      if (e.target.value) {
                        handleBulkAssign(e.target.value, e.target.options[e.target.selectedIndex].text);
                      }
                    }}
                  >
                    <option value="">Select assignee...</option>
                    <option value="1">John Doe</option>
                    <option value="2">Jane Smith</option>
                    <option value="3">Mike Johnson</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Update Status</label>
                  <select 
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"
                    onChange={(e) => {
                      if (e.target.value) {
                        handleBulkStatusUpdate(e.target.value);
                      }
                    }}
                  >
                    <option value="">Select status...</option>
                    <option value="pending">Pending</option>
                    <option value="in_progress">In Progress</option>
                    <option value="completed">Completed</option>
                    <option value="failed">Failed</option>
                  </select>
                </div>
                
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Update Priority</label>
                  <select 
                    className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"
                    onChange={(e) => {
                      if (e.target.value) {
                        handleBulkPriorityUpdate(e.target.value);
                      }
                    }}
                  >
                    <option value="">Select priority...</option>
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </select>
                </div>
              </div>
              
              <div className="flex justify-end space-x-2 mt-4">
                <button
                  onClick={() => setShowBulkActions(false)}
                  className="px-4 py-2 text-gray-600 hover:text-gray-800 transition-colors"
                >
                  Cancel
                </button>
                <button
                  onClick={() => {
                    setSelectedTasks([]);
                    setShowBulkActions(false);
                  }}
                  className="px-4 py-2 bg-gray-200 hover:bg-gray-300 text-gray-700 rounded-lg transition-colors"
                >
                  Clear Selection
                </button>
              </div>
            </div>
          )}
          
          {/* Tasks Table */}
          <div className="bg-white rounded-xl shadow-lg overflow-hidden">
            <div className="px-6 py-4 bg-gray-50 border-b border-gray-200">
              <div className="flex items-center space-x-4">
                <input
                  type="checkbox"
                  checked={selectedTasks.length === tasks.length}
                  onChange={handleSelectAll}
                  className="w-5 h-5 text-blue-600"
                />
                <span className="font-medium text-gray-900">Tasks</span>
              </div>
            </div>
            
            <div className="divide-y divide-gray-200">
              {tasks.map(task => (
                <div key={task.id} className="px-6 py-4 hover:bg-gray-50">
                  <div className="flex items-center space-x-4">
                    <input
                      type="checkbox"
                      checked={selectedTasks.includes(task.id)}
                      onChange={() => handleTaskSelect(task.id)}
                      className="w-5 h-5 text-blue-600"
                    />
                    
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <div>
                          <h4 className="text-lg font-medium text-gray-900">{task.name}</h4>
                          <div className="flex items-center space-x-4 mt-1">
                            <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                              task.status === 'completed' ? 'bg-green-100 text-green-800' :
                              task.status === 'in_progress' ? 'bg-blue-100 text-blue-800' :
                              task.status === 'failed' ? 'bg-red-100 text-red-800' : 'bg-gray-100 text-gray-800'
                            }`}>
                              {task.status.replace('_', ' ')}
                            </span>
                            
                            <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                              task.priority === 'critical' ? 'bg-red-100 text-red-800' :
                              task.priority === 'high' ? 'bg-orange-100 text-orange-800' :
                              task.priority === 'medium' ? 'bg-yellow-100 text-yellow-800' : 'bg-gray-100 text-gray-800'
                            }`}>
                              {task.priority}
                            </span>
                            
                            <span className="text-sm text-gray-600">
                              {task.estimated}min
                            </span>
                          </div>
                        </div>
                        
                        <div className="text-right">
                          <p className="text-sm font-medium text-gray-900">
                            {task.assignee || 'Unassigned'}
                          </p>
                          <button className="text-blue-600 hover:text-blue-800 text-sm">
                            Edit
                          </button>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      );
    }

    return (
      <div className="p-6 space-y-6">
        <div className="flex items-center justify-between">
          <h1 className="text-3xl font-bold text-gray-900 flex items-center space-x-3">
            <Layers className="w-8 h-8 text-blue-600" />
            <span>Playbooks</span>
          </h1>
          <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2">
            <Plus className="w-4 h-4" />
            <span>New Playbook</span>
          </button>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {playbooks.map(playbook => (
            <div key={playbook.id} className="bg-white rounded-xl shadow-lg p-6 hover:shadow-xl transition-shadow cursor-pointer">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-lg font-semibold text-gray-900">{playbook.name}</h3>
                  <p className="text-sm text-gray-600">Version {playbook.version}</p>
                </div>
                <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-medium ${
                  playbook.status === 'active' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                }`}>
                  <div className={`w-2 h-2 rounded-full ${
                    playbook.status === 'active' ? 'bg-green-500' : 'bg-gray-400'
                  }`} />
                  <span>{playbook.status}</span>
                </div>
              </div>
              
              <div className="space-y-3">
                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-600">Tasks:</span>
                  <span className="font-medium text-gray-900">{playbook.tasks}</span>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <span className="text-gray-600">Created:</span>
                  <span className="text-gray-900">{playbook.created}</span>
                </div>
              </div>
              
              <div className="flex space-x-2 mt-4">
                <button
                  onClick={() => setCurrentPlaybook(playbook)}
                  className="flex-1 bg-blue-100 text-blue-700 hover:bg-blue-200 px-4 py-2 rounded-lg text-sm font-medium transition-colors"
                >
                  Open
                </button>
                <button className="px-4 py-2 bg-gray-100 text-gray-700 hover:bg-gray-200 rounded-lg text-sm font-medium transition-colors">
                  Clone
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  };

  // IOCs page
  const IOCs = () => (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900 flex items-center space-x-3">
          <Target className="w-8 h-8 text-blue-600" />
          <span>Indicators of Compromise</span>
        </h1>
        <div className="flex space-x-2">
          <button className="bg-green-600 hover:bg-green-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2">
            <Upload className="w-4 h-4" />
            <span>Import IOCs</span>
          </button>
          <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2">
            <Plus className="w-4 h-4" />
            <span>Add IOC</span>
          </button>
        </div>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {[
          { type: 'IP Address', count: 15, color: 'blue' },
          { type: 'File Hash', count: 8, color: 'green' },
          { type: 'Domain', count: 12, color: 'purple' },
          { type: 'URL', count: 23, color: 'orange' }
        ].map((ioc, index) => (
          <div key={index} className="bg-white rounded-lg shadow p-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-gray-600">{ioc.type}</p>
                <p className="text-2xl font-bold text-gray-900">{ioc.count}</p>
              </div>
              <div className={`p-2 bg-${ioc.color}-100 rounded-lg`}>
                <AlertTriangle className={`w-5 h-5 text-${ioc.color}-600`} />
              </div>
            </div>
          </div>
        ))}
      </div>
      
      <div className="bg-white rounded-xl shadow-lg p-6">
        <h3 className="text-lg font-semibold text-gray-900 mb-4">Recent IOCs</h3>
        <div className="space-y-3">
          {[
            { value: '192.168.1.100', type: 'IP', severity: 'high', source: 'MISP' },
            { value: 'malware.exe', type: 'File', severity: 'critical', source: 'VirusTotal' },
            { value: 'evil.com', type: 'Domain', severity: 'medium', source: 'Manual' },
            { value: 'http://bad-site.net/payload', type: 'URL', severity: 'high', source: 'MISP' }
          ].map((ioc, index) => (
            <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
              <div className="flex items-center space-x-4">
                <div className={`w-2 h-2 rounded-full ${
                  ioc.severity === 'critical' ? 'bg-red-500' :
                  ioc.severity === 'high' ? 'bg-orange-500' : 'bg-yellow-500'
                }`} />
                <div>
                  <p className="font-medium text-gray-900">{ioc.value}</p>
                  <p className="text-sm text-gray-600">{ioc.type} • {ioc.source}</p>
                </div>
              </div>
              <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                ioc.severity === 'critical' ? 'bg-red-100 text-red-800' :
                ioc.severity === 'high' ? 'bg-orange-100 text-orange-800' : 'bg-yellow-100 text-yellow-800'
              }`}>
                {ioc.severity}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );

  // Integrations page
  const Integrations = () => {
    const [selectedIOCs, setSelectedIOCs] = useState([]);
    const [enrichmentInProgress, setEnrichmentInProgress] = useState(false);
    const [huntingInProgress, setHuntingInProgress] = useState(false);
    const [enrichmentResults, setEnrichmentResults] = useState(null);
    const [huntingResults, setHuntingResults] = useState(null);
    
    const integrations = [
      { id: 'misp', name: 'MISP', type: 'Threat Intel', status: 'active', icon: Database, color: 'green' },
      { id: 'virustotal', name: 'VirusTotal', type: 'Threat Intel', status: 'active', icon: Shield, color: 'blue' },
      { id: 'anyrun', name: 'Any.Run', type: 'Sandbox', status: 'active', icon: Activity, color: 'purple' },
      { id: 'greynoise', name: 'GreyNoise', type: 'IP Intel', status: 'active', icon: Globe, color: 'orange' },
      { id: 'hybrid', name: 'Hybrid Analysis', type: 'Malware', status: 'inactive', icon: Search, color: 'gray' },
      { id: 'sentinelone', name: 'SentinelOne', type: 'EDR', status: 'active', icon: Eye, color: 'green' },
      { id: 'crowdstrike', name: 'CrowdStrike', type: 'EDR', status: 'active', icon: Target, color: 'red' },
      { id: 'sophos', name: 'Sophos Central', type: 'XDR', status: 'active', icon: Lock, color: 'blue' }
    ];
    
    const sampleIOCs = [
      { id: 1, value: '192.168.1.100', type: 'IP', severity: 'high', selected: false },
      { id: 2, value: 'malware.exe', type: 'File', severity: 'critical', selected: false },
      { id: 3, value: 'evil.com', type: 'Domain', severity: 'medium', selected: false },
      { id: 4, value: '5d41402abc4b2a76b9719d911017c592', type: 'Hash', severity: 'high', selected: false }
    ];
    
    const [iocs, setIOCs] = useState(sampleIOCs);
    
    const handleIOCSelect = (iocId) => {
      setIOCs(prev => prev.map(ioc => 
        ioc.id === iocId ? { ...ioc, selected: !ioc.selected } : ioc
      ));
    };
    
    const handleSelectAllIOCs = () => {
      const allSelected = iocs.every(ioc => ioc.selected);
      setIOCs(prev => prev.map(ioc => ({ ...ioc, selected: !allSelected })));
    };
    
    const selectedIOCsList = iocs.filter(ioc => ioc.selected);
    
    const handleEnrichIOCs = async () => {
      setEnrichmentInProgress(true);
      
      // Simulate API call
      setTimeout(() => {
        setEnrichmentResults({
          success: true,
          enriched: selectedIOCsList.length,
          results: selectedIOCsList.map(ioc => ({
            ...ioc,
            misp_score: Math.floor(Math.random() * 100),
            vt_detections: Math.floor(Math.random() * 20),
            reputation: ['clean', 'suspicious', 'malicious'][Math.floor(Math.random() * 3)]
          }))
        });
        setEnrichmentInProgress(false);
      }, 3000);
    };
    
    const handleHuntThreats = async () => {
      setHuntingInProgress(true);
      
      // Simulate API call
      setTimeout(() => {
        setHuntingResults({
          success: true,
          hunted: selectedIOCsList.length,
          matches: Math.floor(Math.random() * 5),
          platforms: ['SentinelOne', 'CrowdStrike'],
          results: selectedIOCsList.map(ioc => ({
            ...ioc,
            matches_found: Math.floor(Math.random() * 3),
            endpoints_affected: Math.floor(Math.random() * 10)
          }))
        });
        setHuntingInProgress(false);
      }, 4000);
    };
    
    return (
      <div className="p-6 space-y-6">
        <h1 className="text-3xl font-bold text-gray-900 flex items-center space-x-3">
          <Zap className="w-8 h-8 text-blue-600" />
          <span>Integrations</span>
        </h1>
        
        {/* Integration Status Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {integrations.map(integration => (
            <div key={integration.id} className="bg-white rounded-lg shadow p-4 border-l-4 border-blue-500">
              <div className="flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <integration.icon className={`w-6 h-6 text-${integration.color}-600`} />
                  <div>
                    <p className="font-medium text-gray-900">{integration.name}</p>
                    <p className="text-xs text-gray-600">{integration.type}</p>
                  </div>
                </div>
                <div className={`w-3 h-3 rounded-full ${
                  integration.status === 'active' ? 'bg-green-500' : 'bg-gray-400'
                }`} />
              </div>
            </div>
          ))}
        </div>
        
        {/* Quick Actions Panel */}
        <div className="bg-white rounded-xl shadow-lg p-6">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-lg font-semibold text-gray-900">Bulk Operations</h3>
            <span className="text-sm text-gray-600">
              {selectedIOCsList.length} IOCs selected
            </span>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <button 
              onClick={handleEnrichIOCs}
              disabled={enrichmentInProgress || selectedIOCsList.length === 0}
              className="bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white p-4 rounded-lg flex items-center space-x-3 transition-colors"
            >
              {enrichmentInProgress ? (
                <RefreshCw className="w-5 h-5 animate-spin" />
              ) : (
                <Database className="w-5 h-5" />
              )}
              <div className="text-left">
                <p className="font-medium">Enrich IOCs</p>
                <p className="text-xs opacity-90">MISP, VT, GreyNoise</p>
              </div>
            </button>
            
            <button 
              onClick={handleHuntThreats}
              disabled={huntingInProgress || selectedIOCsList.length === 0}
              className="bg-orange-600 hover:bg-orange-700 disabled:bg-gray-400 text-white p-4 rounded-lg flex items-center space-x-3 transition-colors"
            >
              {huntingInProgress ? (
                <RefreshCw className="w-5 h-5 animate-spin" />
              ) : (
                <Target className="w-5 h-5" />
              )}
              <div className="text-left">
                <p className="font-medium">Hunt Threats</p>
                <p className="text-xs opacity-90">SentinelOne, CrowdStrike</p>
              </div>
            </button>
            
            <button 
              disabled={selectedIOCsList.length === 0}
              className="bg-red-600 hover:bg-red-700 disabled:bg-gray-400 text-white p-4 rounded-lg flex items-center space-x-3 transition-colors"
            >
              <Lock className="w-5 h-5" />
              <div className="text-left">
                <p className="font-medium">Quarantine & Isolate</p>
                <p className="text-xs opacity-90">Block threats</p>
              </div>
            </button>
          </div>
        </div>
        
        {/* IOCs Selection Table */}
        <div className="bg-white rounded-xl shadow-lg overflow-hidden">
          <div className="px-6 py-4 bg-gray-50 border-b border-gray-200">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <input
                  type="checkbox"
                  checked={selectedIOCsList.length === iocs.length}
                  onChange={handleSelectAllIOCs}
                  className="w-5 h-5 text-blue-600"
                />
                <span className="font-medium text-gray-900">IOCs for Analysis</span>
              </div>
              <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2 text-sm">
                <Plus className="w-4 h-4" />
                <span>Add IOC</span>
              </button>
            </div>
          </div>
          
          <div className="divide-y divide-gray-200">
            {iocs.map(ioc => (
              <div key={ioc.id} className="px-6 py-4 hover:bg-gray-50">
                <div className="flex items-center space-x-4">
                  <input
                    type="checkbox"
                    checked={ioc.selected}
                    onChange={() => handleIOCSelect(ioc.id)}
                    className="w-5 h-5 text-blue-600"
                  />
                  
                  <div className="flex-1">
                    <div className="flex items-center justify-between">
                      <div>
                        <p className="font-medium text-gray-900">{ioc.value}</p>
                        <div className="flex items-center space-x-4 mt-1">
                          <span className="px-2 py-1 text-xs font-medium bg-blue-100 text-blue-800 rounded-full">
                            {ioc.type}
                          </span>
                          <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                            ioc.severity === 'critical' ? 'bg-red-100 text-red-800' :
                            ioc.severity === 'high' ? 'bg-orange-100 text-orange-800' :
                            ioc.severity === 'medium' ? 'bg-yellow-100 text-yellow-800' : 'bg-gray-100 text-gray-800'
                          }`}>
                            {ioc.severity}
                          </span>
                        </div>
                      </div>
                      
                      <div className="text-right">
                        <button className="text-blue-600 hover:text-blue-800 text-sm">
                          Details
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
        
        {/* Results Panels */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Enrichment Results */}
          {enrichmentResults && (
            <div className="bg-white rounded-xl shadow-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center space-x-2">
                <Database className="w-5 h-5 text-blue-600" />
                <span>Enrichment Results</span>
              </h3>
              
              <div className="space-y-4">
                <div className="flex items-center justify-between p-3 bg-green-50 rounded-lg">
                  <span className="text-sm font-medium text-gray-700">IOCs Enriched</span>
                  <span className="text-lg font-bold text-green-600">{enrichmentResults.enriched}</span>
                </div>
                
                {enrichmentResults.results.map((result, index) => (
                  <div key={index} className="border rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-gray-900">{result.value}</span>
                      <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                        result.reputation === 'malicious' ? 'bg-red-100 text-red-800' :
                        result.reputation === 'suspicious' ? 'bg-yellow-100 text-yellow-800' : 'bg-green-100 text-green-800'
                      }`}>
                        {result.reputation}
                      </span>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-gray-600">MISP Score:</span>
                        <span className="ml-2 font-medium">{result.misp_score}/100</span>
                      </div>
                      <div>
                        <span className="text-gray-600">VT Detections:</span>
                        <span className="ml-2 font-medium">{result.vt_detections}/70</span>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          
          {/* Hunting Results */}
          {huntingResults && (
            <div className="bg-white rounded-xl shadow-lg p-6">
              <h3 className="text-lg font-semibold text-gray-900 mb-4 flex items-center space-x-2">
                <Target className="w-5 h-5 text-orange-600" />
                <span>Threat Hunting Results</span>
              </h3>
              
              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="flex items-center justify-between p-3 bg-orange-50 rounded-lg">
                    <span className="text-sm font-medium text-gray-700">IOCs Hunted</span>
                    <span className="text-lg font-bold text-orange-600">{huntingResults.hunted}</span>
                  </div>
                  <div className="flex items-center justify-between p-3 bg-red-50 rounded-lg">
                    <span className="text-sm font-medium text-gray-700">Matches Found</span>
                    <span className="text-lg font-bold text-red-600">{huntingResults.matches}</span>
                  </div>
                </div>
                
                <div className="p-3 bg-blue-50 rounded-lg">
                  <p className="text-sm font-medium text-gray-700 mb-2">Platforms Searched:</p>
                  <div className="flex space-x-2">
                    {huntingResults.platforms.map((platform, index) => (
                      <span key={index} className="px-2 py-1 bg-blue-100 text-blue-800 text-xs font-medium rounded-full">
                        {platform}
                      </span>
                    ))}
                  </div>
                </div>
                
                {huntingResults.results.map((result, index) => (
                  <div key={index} className="border rounded-lg p-4">
                    <div className="flex items-center justify-between mb-2">
                      <span className="font-medium text-gray-900">{result.value}</span>
                      {result.matches_found > 0 && (
                        <span className="px-2 py-1 text-xs font-medium bg-red-100 text-red-800 rounded-full">
                          {result.matches_found} matches
                        </span>
                      )}
                    </div>
                    
                    <div className="text-sm text-gray-600">
                      <span>Endpoints affected: </span>
                      <span className="font-medium">{result.endpoints_affected}</span>
                    </div>
                    
                    {result.matches_found > 0 && (
                      <div className="mt-2 flex space-x-2">
                        <button className="bg-red-600 hover:bg-red-700 text-white px-3 py-1 rounded text-xs">
                          Quarantine
                        </button>
                        <button className="bg-orange-600 hover:bg-orange-700 text-white px-3 py-1 rounded text-xs">
                          Isolate
                        </button>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    );
  };

  // Modules page
  const Modules = () => (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900 flex items-center space-x-3">
          <Package className="w-8 h-8 text-blue-600" />
          <span>Modules</span>
        </h1>
        <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2">
          <Plus className="w-4 h-4" />
          <span>Install Module</span>
        </button>
      </div>
      
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {modules.map(module => (
          <div key={module.id} className="bg-white rounded-xl shadow-lg p-6">
            <div className="flex items-start justify-between mb-4">
              <div>
                <h3 className="text-lg font-semibold text-gray-900">{module.name}</h3>
                <p className="text-sm text-gray-600">Version {module.version}</p>
              </div>
              <div className={`flex items-center space-x-2 px-3 py-1 rounded-full text-xs font-medium ${
                module.status === 'active' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
              }`}>
                <div className={`w-2 h-2 rounded-full ${
                  module.status === 'active' ? 'bg-green-500' : 'bg-gray-400'
                }`} />
                <span>{module.status}</span>
              </div>
            </div>
            
            <p className="text-gray-700 mb-4">{module.description}</p>
            
            <div className="flex space-x-2">
              <button
                onClick={() => {
                  setModules(modules.map(m => 
                    m.id === module.id 
                      ? { ...m, status: m.status === 'active' ? 'inactive' : 'active' }
                      : m
                  ));
                }}
                className={`px-4 py-2 rounded-lg text-sm font-medium ${
                  module.status === 'active' 
                    ? 'bg-red-100 text-red-700 hover:bg-red-200' 
                    : 'bg-green-100 text-green-700 hover:bg-green-200'
                }`}
              >
                {module.status === 'active' ? 'Disable' : 'Enable'}
              </button>
              <button className="px-4 py-2 bg-blue-100 text-blue-700 hover:bg-blue-200 rounded-lg text-sm font-medium">
                Configure
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );

  // Users page
  const Users = () => (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-3xl font-bold text-gray-900 flex items-center space-x-3">
          <Users className="w-8 h-8 text-blue-600" />
          <span>Users</span>
        </h1>
        <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg flex items-center space-x-2">
          <Plus className="w-4 h-4" />
          <span>Add User</span>
        </button>
      </div>
      
      <div className="bg-white rounded-xl shadow-lg overflow-hidden">
        <table className="w-full">
          <thead className="bg-gray-50">
            <tr>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Name</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Email</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Role</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Status</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Last Login</th>
              <th className="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">Actions</th>
            </tr>
          </thead>
          <tbody className="bg-white divide-y divide-gray-200">
            {[
              { name: 'Administrator', email: 'admin@mirage.local', role: 'admin', status: 'active', lastLogin: '2025-08-07' },
              { name: 'John Doe', email: 'john@mirage.local', role: 'analyst', status: 'active', lastLogin: '2025-08-06' },
              { name: 'Jane Smith', email: 'jane@mirage.local', role: 'investigator', status: 'active', lastLogin: '2025-08-05' },
              { name: 'Mike Johnson', email: 'mike@mirage.local', role: 'viewer', status: 'inactive', lastLogin: '2025-08-01' }
            ].map((user, index) => (
              <tr key={index} className="hover:bg-gray-50">
                <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-gray-900">{user.name}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{user.email}</td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className="px-2 py-1 text-xs font-medium bg-blue-100 text-blue-800 rounded-full">
                    {user.role}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap">
                  <span className={`px-2 py-1 text-xs font-medium rounded-full ${
                    user.status === 'active' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'
                  }`}>
                    {user.status}
                  </span>
                </td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">{user.lastLogin}</td>
                <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-900">
                  <button className="text-blue-600 hover:text-blue-900 mr-3">Edit</button>
                  <button className="text-red-600 hover:text-red-900">Delete</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );

  // Settings page
  const Settings = () => (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold text-gray-900 flex items-center space-x-3">
        <Settings className="w-8 h-8 text-blue-600" />
        <span>Settings</span>
      </h1>
      
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="bg-white rounded-xl shadow-lg p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">System Configuration</h3>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Database Host</label>
              <input 
                type="text" 
                defaultValue="localhost:5432"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">RabbitMQ URL</label>
              <input 
                type="text" 
                defaultValue="amqp://localhost:5672"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Session Timeout (minutes)</label>
              <input 
                type="number" 
                defaultValue="60"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>
        </div>
        
        <div className="bg-white rounded-xl shadow-lg p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Security Settings</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-gray-900">Two-Factor Authentication</p>
                <p className="text-sm text-gray-600">Enable 2FA for all users</p>
              </div>
              <input type="checkbox" className="w-5 h-5 text-blue-600" />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-gray-900">Password Complexity</p>
                <p className="text-sm text-gray-600">Require strong passwords</p>
              </div>
              <input type="checkbox" defaultChecked className="w-5 h-5 text-blue-600" />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-gray-900">Audit Logging</p>
                <p className="text-sm text-gray-600">Log all user actions</p>
              </div>
              <input type="checkbox" defaultChecked className="w-5 h-5 text-blue-600" />
            </div>
          </div>
        </div>
        
        <div className="bg-white rounded-xl shadow-lg p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Backup Configuration</h3>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Backup Schedule</label>
              <select className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500">
                <option>Daily at 2:00 AM</option>
                <option>Weekly on Sunday</option>
                <option>Monthly on 1st</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">Retention Period (days)</label>
              <input 
                type="number" 
                defaultValue="30"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>
        </div>
        
        <div className="bg-white rounded-xl shadow-lg p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Integration Settings</h3>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">MISP Instance URL</label>
              <input 
                type="url" 
                placeholder="https://misp.example.com"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">VirusTotal API Key</label>
              <input 
                type="password" 
                placeholder="Enter API key"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">SentinelOne API Token</label>
              <input 
                type="password" 
                placeholder="Enter API token"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-1">CrowdStrike Client ID</label>
              <input 
                type="text" 
                placeholder="Enter client ID"
                className="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:border-blue-500"
              />
            </div>
          </div>
        </div>
        
        <div className="bg-white rounded-xl shadow-lg p-6">
          <h3 className="text-lg font-semibold text-gray-900 mb-4">Notification Settings</h3>
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-gray-900">Email Notifications</p>
                <p className="text-sm text-gray-600">Send email alerts for critical events</p>
              </div>
              <input type="checkbox" defaultChecked className="w-5 h-5 text-blue-600" />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-gray-900">Slack Integration</p>
                <p className="text-sm text-gray-600">Post alerts to Slack channels</p>
              </div>
              <input type="checkbox" className="w-5 h-5 text-blue-600" />
            </div>
            <div className="flex items-center justify-between">
              <div>
                <p className="font-medium text-gray-900">Teams Integration</p>
                <p className="text-sm text-gray-600">Send notifications to Microsoft Teams</p>
              </div>
              <input type="checkbox" className="w-5 h-5 text-blue-600" />
            </div>
          </div>
        </div>
      </div>
      
      <div className="flex justify-end space-x-2">
        <button className="px-6 py-2 border border-gray-300 text-gray-700 rounded-lg hover:bg-gray-50 transition-colors">
          Reset to Defaults
        </button>
        <button className="bg-blue-600 hover:bg-blue-700 text-white px-6 py-2 rounded-lg font-medium transition-colors">
          Save Settings
        </button>
      </div>
    </div>
  );

  // Main render
  if (!isLoggedIn) {
    return <LoginPage />;
  }

  const renderPage = () => {
    switch (currentPage) {
      case 'dashboard': return <Dashboard />;
      case 'cases': return <Cases />;
      case 'playbooks': return <Playbooks />;
      case 'iocs': return <IOCs />;
      case 'integrations': return <Integrations />;
      case 'modules': return <Modules />;
      case 'users': return <Users />;
      case 'settings': return <Settings />;
      default: return <Dashboard />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-100">
      <Navigation />
      <main className="pb-8">
        {renderPage()}
      </main>
      
      {/* Footer */}
      <footer className="bg-white border-t border-gray-200">
        <div className="max-w-7xl mx-auto py-6 px-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Shield className="w-5 h-5 text-blue-600" />
              <span className="text-sm font-medium text-gray-900">mIRage DFIR Platform</span>
              <span className="text-sm text-gray-500">v2.0.0</span>
            </div>
            
            <div className="flex items-center space-x-6 text-sm text-gray-600">
              <a href="#" className="hover:text-gray-900 transition-colors">Documentation</a>
              <a href="#" className="hover:text-gray-900 transition-colors">API Reference</a>
              <a href="#" className="hover:text-gray-900 transition-colors">Support</a>
              <a href="https://github.com/scllpadmin/mIRage" className="hover:text-gray-900 transition-colors flex items-center space-x-1">
                <GitBranch className="w-4 h-4" />
                <span>GitHub</span>
              </a>
            </div>
          </div>
          
          <div className="mt-4 pt-4 border-t border-gray-200">
            <p className="text-xs text-gray-500 text-center">
              Built with ❤️ by the cybersecurity community for defenders everywhere. 
              Licensed under LGPL3. Do not expose to the internet without proper security measures.
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
};

export default mIRage;
