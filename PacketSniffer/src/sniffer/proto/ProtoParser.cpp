#include <pch.h>
#include "ProtoParser.h"
#include <memory>
#include <google/protobuf/util/type_resolver_util.h>

using namespace google::protobuf;
namespace sniffer
{
	class ErrorCollector : public compiler::MultiFileErrorCollector
	{
		// Inherited via MultiFileErrorCollector
		void AddError(const std::string& filename, int line, int column, const std::string& message) override
		{
			printf("Error while parsing %s file, line %d, column %d, error: %s\n", filename.c_str(), line, column, message.c_str());
		}
	};

	void ProtoParser::LoadProtoDir(const std::string& dirPath)
	{
		const std::lock_guard<std::mutex> lock(_mutex);

		m_DiskTree = std::make_shared<compiler::DiskSourceTree>();
		if (!dirPath.empty())
			m_DiskTree->MapPath("", dirPath);

		auto errorCollector = new ErrorCollector();
		m_Importer = std::make_shared<compiler::Importer>(m_DiskTree.get(), errorCollector);
		m_Factory = std::make_shared<DynamicMessageFactory>(m_Importer->pool());

		m_ProtoDirPath = dirPath;
	}

	void Split(const std::string& src, const std::string& separator, std::vector<std::string>& dest)
	{
		std::string str = src;
		std::string substring;
		std::string::size_type start = 0, index;
		dest.clear();
		index = str.find_first_of(separator, start);
		do
		{
			if (index != std::string::npos)
			{
				substring = str.substr(start, index - start);
				dest.push_back(substring);
				start = index + separator.size();
				index = str.find(separator, start);
				if (start == std::string::npos) break;
			}
		} while (index != std::string::npos);
		substring = str.substr(start);
		dest.push_back(substring);
	}

	void ProtoParser::LoadIDsFromFile(const std::string& filepath)
	{
		m_IDFilePath = filepath;

		if (filepath.empty())
			return;

		const std::lock_guard<std::mutex> lock(_mutex);
		m_NameMap.clear();
		m_IdMap.clear();

		std::ifstream file;
		file.open(filepath);
		if (!file.is_open())
		{
			LOG_WARNING("Failed to load proto id file.");
			return;
		}
		if (filepath.find(".json") != std::string::npos)
		{
			auto content = nlohmann::json::parse(file);
			for (nlohmann::json::iterator it = content.begin(); it != content.end(); ++it)
			{
				auto id = it.value().is_number() ? static_cast<uint32_t>(it.value()) : std::stoul(it.key());
				auto name = it.value().is_number() ? it.key() : static_cast<std::string>(it.value());;
				m_NameMap[id] = name;
				m_IdMap[name] = id;
			}
		}
		else if (filepath.find(".csv") != std::string::npos)
		{
			std::string line;
			while (std::getline(file, line)) {
				std::vector<std::string> ret;
				Split(line, ",", ret);
				auto id = std::stoi(ret[1]);
				m_NameMap[id] = ret[0];
				m_IdMap[ret[0]] = id;
			}
		}
		file.close();
	}

	void ProtoParser::LoadIDsFromFile()
	{
		LoadIDsFromFile(m_IDFilePath);
	}

	void ProtoParser::LoadIDsFromCmdID()
	{
		namespace fs = std::filesystem;
		if (m_ProtoDirPath.empty() || !fs::is_directory(m_ProtoDirPath))
			return;

		const std::lock_guard<std::mutex> lock(_mutex);
		m_NameMap.clear();
		m_IdMap.clear();

		for (const auto& entry : fs::directory_iterator(m_ProtoDirPath))
		{
			if (!entry.is_regular_file() || entry.path().extension() != ".proto")
				continue;

			std::ifstream fileStream(entry.path());
			if (!fileStream.is_open())
				continue;

			std::stringstream buffer;
			buffer << fileStream.rdbuf();

			// Unoptimized variant (very slow)
			//auto regexData = std::regex("CMD_ID = ([0-9]+);", std::regex_constants::ECMAScript);
			//std::string content = buffer.str();
			//std::smatch cmdIDMatch;
			//if (!std::regex_search(content, cmdIDMatch, regexData))
			//	continue;
			//
			auto filename = entry.path().stem().string();
			//auto messageId = std::stoi(cmdIDMatch[1]);

			// Optimized code
			constexpr std::array<std::pair<const char*, size_t>, 2> cmdIDPatterns = {
				{
					{ "CMD_ID = ", 9 },
					{ "// CmdId: ", 10 }
				}
			};

			std::string line;
			while (std::getline(buffer, line))
			{
				size_t start_index = 0;
				for (auto& ch : line)
				{
					if (ch != ' ' && ch != '\t')
						break;
					start_index++;
				}

				size_t index = 0;
				for (auto& [pattern, patternSize] : cmdIDPatterns)
				{

					if (start_index + patternSize > line.size())
						continue;


					if (std::memcmp(line.data() + start_index, pattern, patternSize) != 0)
						continue;


					index = start_index + patternSize;
					break;
				}

				if (index == 0)
					continue;

				int messageId = 0;

				char ch;
				// Native stoi
				while (line.size() > index && (ch = line.data()[index], ch >= '0' && ch <= '9'))
				{
					messageId = messageId * 10 + static_cast<int>(ch - '0');
					index++;
				}

				m_NameMap[messageId] = filename;
				m_IdMap[filename] = messageId;
				break;
			}
		}
	}

	Message* ProtoParser::ParseMessage(const std::string& name, const std::vector<byte>& data)
	{
		const std::lock_guard<std::mutex> lock(_mutex);

		auto fileDescriptor = m_Importer->Import(name + ".proto");
		if (fileDescriptor == nullptr || fileDescriptor->message_type_count() == 0)
			return nullptr;

		auto message = m_Factory->GetPrototype(fileDescriptor->message_type(0))->New();

		std::string stringData((char*)data.data(), data.size());
		message->ParseFromString(stringData);

		return message;
	}

	ProtoParser::ProtoParser()
	{

	}

	void ProtoParser::Load(const std::string& idFilePath, const std::string& protoDir)
	{
		LoadIDsFromFile(idFilePath);
		LoadProtoDir(protoDir);
	}

	void ProtoParser::Load(const std::string& protoDir)
	{
		LoadProtoDir(protoDir);
		LoadIDsFromCmdID();
	}

	struct ConvertResult
	{
		bool hasUnknownFields;
		bool hasUnsettedFields;

		void concat(const ConvertResult& other)
		{
			hasUnknownFields |= other.hasUnknownFields;
			hasUnsettedFields |= other.hasUnsettedFields;
		}
	};

	static ConvertResult ConvertMessage(ProtoNode& node, const Message& message);

	bool ProtoParser::Parse(const std::string& name, const std::vector<byte>& data, ProtoMessage& message)
	{
		auto raw_message = name.empty() ? ParseMessage("Empty", data) : ParseMessage(name, data);
		if (raw_message == nullptr)
		{
			LOG_ERROR("Failed to parse message with name %s.", name.c_str());
			return false;
		}

		auto result = ConvertMessage(message, *raw_message);

		message.set_flag(ProtoMessage::Flag::HasUnknown, result.hasUnknownFields);
		message.set_flag(ProtoMessage::Flag::HasUnsetted, result.hasUnsettedFields);

		delete raw_message;

		return true;
	}

	bool ProtoParser::Parse(uint32_t id, const std::vector<byte>& data, ProtoMessage& message)
	{
		auto name = GetName(id);
		return Parse(name ? *name : std::string(), data, message);
	}

	std::optional<std::string> ProtoParser::GetName(uint32_t id)
	{
		const std::lock_guard<std::mutex> lock(_mutex);

		if (m_NameMap.count(id) == 0)
		{
			LOG_WARNING("Failed to find proto with id %u", id);
			return {};
		}

		return m_NameMap[id];
	}

	uint16_t ProtoParser::GetId(const std::string& name)
	{
		return m_IdMap.count(name) == 0 ? 0 : m_IdMap[name];
	}

	static std::string GetFieldName(const FieldDescriptor* field);
	static bool IsStringPrintable(const std::string& string);

#undef GetMessage

	static bool ConcatUnknownFields(ProtoNode& node, const UnknownFieldSet& unknownFields);
	static bool ConcatDefaultFields(ProtoNode& node, const Message& message, const std::unordered_set<int>& visited_field_numbers);
	static ConvertResult ConvertValue(ProtoValue& proto_value, const Message& message,
		const Reflection* reflection, const FieldDescriptor* field, int index);
	static ConvertResult ConvertField(ProtoValue& proto_value, const FieldDescriptor* field, const Message& message, const Reflection* reflection);

	static ConvertResult ConvertMapEntry(ProtoValue::map_type& map, const Message& message)
	{
		const Reflection* reflection = message.GetReflection();
		const Descriptor* descriptor = message.GetDescriptor();
		std::vector<const FieldDescriptor*> fields;
		if (!descriptor->options().map_entry())
			return {};

		ConvertResult result{};

		ProtoValue key;
		result.concat(ConvertValue(key, message, reflection, descriptor->field(0), -1));

		ProtoValue value;
		result.concat(ConvertField(value, descriptor->field(1), message, reflection));

		map.insert(std::make_pair(std::move(key), std::move(value)));

		return result;
	}

	static ConvertResult ConvertField(ProtoValue& proto_value, const FieldDescriptor* field, const Message& message, const Reflection* reflection)
	{
		ConvertResult result{};
		int count = 0;

		if (field->is_repeated()) {
			count = reflection->FieldSize(message, field);
		}
		else if (reflection->HasField(message, field) ||
			field->containing_type()->options().map_entry()) {
			count = 1;
		}

		bool repeated = field->is_repeated();
		bool is_map = field->is_map();
		bool is_list = repeated && !is_map;

		if (is_map)
			proto_value = ProtoValue(ProtoValue::map_type());

		if (is_list)
			proto_value = ProtoValue(ProtoValue::list_type());

		for (int j = 0; j < count; ++j) {
			const int field_index = field->is_repeated() ? j : -1;

			if (field->cpp_type() == FieldDescriptor::CPPTYPE_MESSAGE)
			{

				auto& sub_message = field->is_repeated() ?
					reflection->GetRepeatedMessage(message, field, j) :
					reflection->GetMessage(message, field);

				if (is_map)
				{
					result.concat(ConvertMapEntry(proto_value.to_map(), sub_message));
				}
				else
				{
					auto new_node = ProtoNode();
					result.concat(ConvertMessage(new_node, sub_message));

					if (is_list)
					{
						auto& list = proto_value.to_list();
						list.emplace_back(std::move(new_node));
					}
					else
					{
						proto_value = ProtoValue(std::move(new_node));
					}
				}
			}
			else
			{
				result.concat(ConvertValue(proto_value, message, reflection, field, field_index));
			}
		}
		return result;
	}

	static ConvertResult ConvertMessage(ProtoNode& node, const Message& message)
	{
		ConvertResult result{};

		const Reflection* reflection = message.GetReflection();
		if (reflection == nullptr)
		{
			UnknownFieldSet unknown_fields;
			{
				std::string serialized = message.SerializeAsString();
				io::ArrayInputStream input(serialized.data(), serialized.size());
				unknown_fields.ParseFromZeroCopyStream(&input);
			}

			result.hasUnknownFields = ConcatUnknownFields(node, unknown_fields);
			return result;
		}

		std::vector<const FieldDescriptor*> fields;
		reflection->ListFields(message, &fields);

		node.set_type(message.GetTypeName());

		std::unordered_set<int> visited_field_numbers;
		for (const FieldDescriptor* field : fields)
		{
			visited_field_numbers.insert(field->number());

			auto& proto_field = node.emplace_field(field->number(), GetFieldName(field));
			result.concat(ConvertField(proto_field.value(), field, message, reflection));
		}

		result.hasUnknownFields |= ConcatUnknownFields(node, reflection->GetUnknownFields(message));
		result.hasUnsettedFields |= ConcatDefaultFields(node, message, visited_field_numbers);
		return result;
	}

	static bool ConcatUnknownFields(ProtoNode& node, const UnknownFieldSet& unknownFields)
	{
		for (int i = 0; i < unknownFields.field_count(); i++)
		{
			auto& field = unknownFields.field(i);

			std::string name;
			ProtoValue field_value;
			switch (field.type()) {
			case UnknownField::TYPE_VARINT:
			{
				name = "varInt";
				field_value = field.varint();
			}
			break;

			case UnknownField::TYPE_FIXED32:
			{
				auto temp_val = field.fixed32();
				name = "fixed32";
				field_value = ::util::ReadMapped<float>(&temp_val, 0, true);
			}
			break;

			case UnknownField::TYPE_FIXED64:
			{
				auto temp_val = field.fixed64();
				name = "fixed64";
				field_value = ::util::ReadMapped<double>(&temp_val, 0, true);
			}
			break;

			case UnknownField::TYPE_GROUP:
			{
				ProtoNode new_node = ProtoNode();
				ConcatUnknownFields(new_node, field.group());
				field_value = std::move(new_node);
				name = "group";
			}
			break;
			case UnknownField::TYPE_LENGTH_DELIMITED:
			{
				const std::string& value = field.length_delimited();
				io::CodedInputStream input_stream(
					reinterpret_cast<const uint8_t*>(value.data()), value.size());
				UnknownFieldSet embedded_unknown_fields;
				if (!value.empty() &&
					embedded_unknown_fields.ParseFromCodedStream(&input_stream))
				{
					ProtoNode new_node = ProtoNode();
					ConcatUnknownFields(new_node, embedded_unknown_fields);
					field_value = std::move(new_node);
					name = "lgroup";
				}
				else
				{
					if (IsStringPrintable(value))
					{
						name = "string";
						field_value = value;
					}
					else
					{
						name = "bytes";
						field_value = std::vector<byte>(value.begin(), value.end());
					}
				}
			}
			break;
			}

			auto& proto_field = node.emplace_field(field.number(), fmt::format("unk_{}[{}]", name, field.number()), std::move(field_value));
			proto_field.set_flag(ProtoField::Flag::Unknown, true);
		}

		return unknownFields.field_count() > 0;
	}

	static const char* kTypeUrlPrefix = "type.googleapis.com";
	static google::protobuf::util::TypeResolver* generated_type_resolver_ = nullptr;
	static bool type_resolver_called_once_ = false;

	static void DeleteGeneratedTypeResolver() { delete generated_type_resolver_; }

	static google::protobuf::util::TypeResolver* GetGeneratedTypeResolver()
	{
		if (!type_resolver_called_once_)
		{
			generated_type_resolver_ = google::protobuf::util::NewTypeResolverForDescriptorPool(
				kTypeUrlPrefix, DescriptorPool::generated_pool());
			::google::protobuf::internal::OnShutdown(&DeleteGeneratedTypeResolver);
		}
		return generated_type_resolver_;
	}

	static std::string GetTypeUrl(const Message& message) {
		return std::string(kTypeUrlPrefix) + "/" +
			message.GetDescriptor()->full_name();
	}

	static void GetTypeByUrl(const Message& message, const std::string& type_url, google::protobuf::Type& type)
	{
		const DescriptorPool* pool = message.GetDescriptor()->file()->pool();
		google::protobuf::util::TypeResolver* resolver =
			pool == DescriptorPool::generated_pool()
			? GetGeneratedTypeResolver()
			: google::protobuf::util::NewTypeResolverForDescriptorPool(kTypeUrlPrefix, pool);

		resolver->ResolveMessageType(type_url, &type);
	}

	static void GetEnumByUrl(const Message& message, const std::string& type_url, google::protobuf::Enum& enum_type)
	{
		const DescriptorPool* pool = message.GetDescriptor()->file()->pool();
		google::protobuf::util::TypeResolver* resolver =
			pool == DescriptorPool::generated_pool()
			? GetGeneratedTypeResolver()
			: google::protobuf::util::NewTypeResolverForDescriptorPool(kTypeUrlPrefix, pool);

		resolver->ResolveEnumType(type_url, &enum_type);
	}

	static bool ConcatDefaultFields(ProtoNode& node, const Message& message, const google::protobuf::Type& type, const std::unordered_set<int>& visited_field_numbers)
	{
		bool has_unsetted = false;
		for (size_t i = 0; i < type.fields_size(); i++)
		{
			auto& field = type.fields().at(i);
			if (visited_field_numbers.count(field.number()) > 0)
				continue;

			has_unsetted = true;

			ProtoValue container;

			if (field.cardinality() == field.CARDINALITY_REPEATED)
			{
				bool is_map = false;
				if (field.kind() == google::protobuf::Field::TYPE_MESSAGE)
				{
					google::protobuf::Type nested_type;
					GetTypeByUrl(message, field.type_url(), nested_type);

					is_map = nested_type.name().find("MapEntry") != std::string::npos;
				}

				if (is_map)
					container = ProtoValue::map_type();
				else
					container = ProtoValue::list_type();
			}
			else
			{
				switch (field.kind())
				{
#define APPLY_TYPE(FIELD_TYPE, CPP_TYPE)                    \
			case google::protobuf::Field::TYPE_##FIELD_TYPE:\
				container = CPP_TYPE{};                     \
				break
					APPLY_TYPE(BOOL, bool);
					APPLY_TYPE(FLOAT, float);
					APPLY_TYPE(DOUBLE, double);
					APPLY_TYPE(INT64, int64_t);
					APPLY_TYPE(UINT64, uint64_t);
					APPLY_TYPE(INT32, int32_t);
					APPLY_TYPE(UINT32, uint32_t);
					APPLY_TYPE(FIXED32, float);
					APPLY_TYPE(FIXED64, double);
					APPLY_TYPE(SFIXED32, int32_t);
					APPLY_TYPE(SFIXED64, int64_t);
					APPLY_TYPE(STRING, std::string);
					APPLY_TYPE(BYTES, std::string);
					APPLY_TYPE(SINT64, int64_t);
					APPLY_TYPE(SINT32, int32_t);

#undef APPLY_TYPE
				case google::protobuf::Field::TYPE_ENUM:
				{
					google::protobuf::Enum enum_type;
					GetEnumByUrl(message, field.type_url(), enum_type);

					uint32_t id = ProtoEnumCache::GetID(enum_type.name());
					if (id == 0)
					{
						std::unordered_map<uint32_t, std::string> values;
						for (auto& value : enum_type.enumvalue())
							values[value.number()] = value.name();

						id = ProtoEnumCache::StoreEnumValues(enum_type.name(), std::move(values));
					}

					container = ProtoEnum(id, field.oneof_index());
					break;
				}
				case google::protobuf::Field::TYPE_MESSAGE:
				{
					google::protobuf::Type nested_type;
					GetTypeByUrl(message, field.type_url(), nested_type);

					container = ProtoNode();
					std::unordered_set<int> visited = {};
					ConcatDefaultFields(container.to_node(), message, nested_type, visited);
					container.to_node().set_type(nested_type.name());
					break;
				}
				default:
					break;
				}
			}


			auto& proto_field = node.emplace_field(field.number(), field.name(), std::move(container));
			proto_field.set_flag(ProtoField::Flag::Unsetted, true);
		}

		return has_unsetted;
	}

	static bool ConcatDefaultFields(ProtoNode& node, const Message& message, const std::unordered_set<int>& visited_field_numbers)
	{
		google::protobuf::Type type;
		GetTypeByUrl(message, GetTypeUrl(message), type);
		return ConcatDefaultFields(node, message, type, visited_field_numbers);
	}

	static bool IsStringPrintable(const std::string& string)
	{
		for (auto& ch : string)
		{
			if (!std::isprint(static_cast<unsigned char>(ch)) && ch != '\n' && ch != '\t' && ch != '\r')
				return false;
		}
		return true;
	}

	static std::string GetFieldName(const FieldDescriptor* field)
	{
		if (field->is_extension()) {
			return field->PrintableNameForExtension();
		}
		else if (field->type() == FieldDescriptor::TYPE_GROUP) {
			// Groups must be serialized with their original capitalization.
			return field->message_type()->name();
		}
		else
		{
			return field->name();
		}
	}

	static ConvertResult ConvertValue(ProtoValue& proto_value, const Message& message,
		const Reflection* reflection, const FieldDescriptor* field, int index)
	{
		ConvertResult result{};

		GOOGLE_DCHECK(field->is_repeated() || (index == -1))
			<< "Index must be -1 for non-repeated fields";

		ProtoValue& value = field->is_repeated() ? proto_value.get<ProtoValue::list_type>().emplace_back() : proto_value;
		switch (field->cpp_type()) {

#define OUTPUT_FIELD(CPPTYPE, METHOD)                                			  			\
case FieldDescriptor::CPPTYPE_##CPPTYPE:										  			\
	value = field->is_repeated() ? reflection->GetRepeated##METHOD(message, field, index) :	\
		reflection->Get##METHOD(message, field);											\
    break

			OUTPUT_FIELD(INT32, Int32);
			OUTPUT_FIELD(INT64, Int64);
			OUTPUT_FIELD(UINT32, UInt32);
			OUTPUT_FIELD(UINT64, UInt64);
			OUTPUT_FIELD(FLOAT, Float);
			OUTPUT_FIELD(DOUBLE, Double);
			OUTPUT_FIELD(BOOL, Bool);
#undef OUTPUT_FIELD

		case FieldDescriptor::CPPTYPE_STRING: {
			std::string scratch;
			const std::string& svalue =
				field->is_repeated()
				? reflection->GetRepeatedStringReference(message, field, index,
					&scratch)
				: reflection->GetStringReference(message, field, &scratch);
			if (field->type() == FieldDescriptor::TYPE_STRING)
				value = svalue;
			else
			{
				value = ProtoValue::bseq_type(svalue.begin(), svalue.end());
			}
			break;
		}

		case FieldDescriptor::CPPTYPE_ENUM: {
			int enum_index =
				field->is_repeated()
				? reflection->GetRepeatedEnumValue(message, field, index)
				: reflection->GetEnumValue(message, field);

			const EnumDescriptor* enum_desc = field->enum_type();
			if (enum_desc != nullptr)
			{
				google::protobuf::Enum enum_type;

				uint32_t id = ProtoEnumCache::GetID(enum_desc->name());
				if (id == 0)
				{
					std::unordered_map<uint32_t, std::string> values;
					for (int i = 0; i < enum_desc->value_count(); ++i)
					{
						const EnumValueDescriptor* enum_value = enum_desc->value(i);
						values[enum_value->number()] = enum_value->name();
					}

					id = ProtoEnumCache::StoreEnumValues(enum_desc->name(), std::move(values));
				}

				value = ProtoEnum(id, enum_index);
			}
			else
				value = fmt::format("UnkEnumValue({})", enum_index);

			break;
		}

		case FieldDescriptor::CPPTYPE_MESSAGE:
			auto new_node = ProtoNode();
			result.concat(ConvertMessage(new_node, message));
			value = new_node;

			break;
		}
		return result;
	}
}