# BPMN Graph Text Representation

## Processes

## Events

## Activities

## Gateways

## Flows
- Sales Department --[IN_POOL]--> Business Process ERP
- Procurement Department --[IN_POOL]--> Business Process ERP
- IT Department --[IN_POOL]--> Business Process ERP
- Finance Department --[IN_POOL]--> Business Process ERP
- System Integration --[IN_POOL]--> Business Process ERP
- Start --[XOR_SPLIT]--> Process Standard Order
- Start --[XOR_SPLIT]--> Process Custom Order
- Process Standard Order --[XOR_JOIN]--> Create Purchase Requisition
- Process Custom Order --[XOR_JOIN]--> Create Purchase Requisition
- Create Purchase Requisition --[AND_SPLIT]--> Generate PO Request
- Create Purchase Requisition --[AND_SPLIT]--> Check Budget Availability
- Create Purchase Requisition --[AND_SPLIT]--> Initiate Inventory Processing
- Generate PO Request --[OR_JOIN]--> Review Purchase Details
- Update Inventory Quantity --[AND_JOIN]--> Finalize Inventory Update
- Check Budget Availability --[OR_JOIN]--> Review Purchase Details
- Review Purchase Details --[XOR_JOIN]--> Verify System Compatibility
- Verify System Compatibility --[XOR_SPLIT]--> Approve Purchase Order
- Verify System Compatibility --[XOR_SPLIT]--> Gateway Connection:  to 
- Approve Purchase Order --[SEQUENCE]--> Validate Financial Impact
- Validate Financial Impact --[AND_SPLIT]--> Complete Purchase Order
- Validate Financial Impact --[AND_SPLIT]--> Start Integration Process
- Complete Purchase Order --[SEQUENCE]--> Notify Vendors
- Start Integration Process --[SEQUENCE]--> Prepare for Integration
- Notify Vendors --[SEQUENCE]--> Update Customer Order Status
- Update Customer Order Status --[SEQUENCE]--> Record Financial Transaction
- Record Financial Transaction --[AND_JOIN]--> End
- Prepare for Integration --[OR_SPLIT]--> Path A Integration
- Prepare for Integration --[OR_SPLIT]--> Path B Integration
- Path A Integration --[OR_CONNECTION]--> Gateway Connection:  to 
- Path B Integration --[OR_CONNECTION]--> Gateway Connection:  to 
- Initiate Inventory Processing --[XOR_SPLIT]--> Update Inventory Quantity
- Initiate Inventory Processing --[XOR_SPLIT]--> Update Inventory Order Status
- Update Inventory Order Status --[AND_JOIN]--> Finalize Inventory Update
- Finalize Inventory Update --[OR_JOIN]--> Review Purchase Details
- Gateway Connection:  to  --[XOR_JOIN]--> Verify System Compatibility
- Gateway Connection:  to  --[AND_JOIN]--> End
- None --[AFFECTS]--> Check Budget Availability

## Graph Structure (Machine-Readable)
### Process Paths
